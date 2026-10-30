package filter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResponseEmbeddedJSON(t *testing.T) {
	f, err := New(Config{Enabled: true, ScanResponses: true, ResponseRules: []Rule{{Name: "dangerous_command", Pattern: `rm\s+-rf\s+/`, Action: "block"}, {Name: "email", Pattern: `[A-Za-z]+@[A-Za-z]+\.[A-Za-z]+`, Action: "redact"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, d := f.Response([]byte(`{"arguments":"{\"command\":\"\\u0072m -rf /\"}"}`))
	if d.Action != Block {
		t.Fatalf("embedded unicode command bypass: %+v", d)
	}
	out, d := f.Response([]byte(`{"arguments":"{\"email\":\"alice\\u0040example.com\"}"}`))
	if d.Action != Redact || strings.Contains(string(out), "alice") {
		t.Fatalf("embedded email bypass: %s %+v", out, d)
	}
	if !json.Valid(out) {
		t.Fatal("redaction corrupted outer JSON")
	}
	var outer map[string]string
	json.Unmarshal(out, &outer)
	if !json.Valid([]byte(outer["arguments"])) {
		t.Fatal("redaction corrupted tool arguments")
	}
}
func TestResponseSchemaReferencesAndPaths(t *testing.T) {
	for _, cfg := range []Config{
		{Enabled: true, ResponseSchema: json.RawMessage(`{"$ref":"https://example.com/schema"}`)},
		{Enabled: true, ResponseSchemaPath: "missing/slash"},
		{Enabled: true, ResponseSchemaPath: "/field"},
		{Enabled: true, ResponseMaxBytes: 9 << 20},
		{Enabled: true, ResponseTimeoutSec: 601},
	} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("invalid response guardrail admitted: %+v", cfg)
		}
	}
}
func TestResponseCredentialBlocked(t *testing.T) {
	f, err := New(Config{Enabled: true, ScanResponses: true})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.ProtectSecret("fixture-specific-proxy-credential")
	if _, d := f.Response([]byte(`{"answer":"fixture-specific-proxy-credential"}`)); d.Action != Block {
		t.Fatal("proxy credential leaked in response")
	}
}

func TestResponseSchemaAfterRedaction(t *testing.T) {
	f, err := New(Config{Enabled: true, ScanResponses: true, ResponseRules: []Rule{{Name: "status", Pattern: "ok", Action: "redact"}}, ResponseSchema: json.RawMessage(`{"type":"object","properties":{"status":{"enum":["ok"]}},"required":["status"]}`)})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, d := f.Response([]byte(`{"status":"ok"}`)); d.Action != Block || d.Rule != "response_schema_mismatch" {
		t.Fatalf("redaction invalidated schema without rejection: %+v", d)
	}
}

func TestNullResponseSchemaIsAbsent(t *testing.T) {
	f, err := New(Config{Enabled: true, ScanResponses: true, ResponseSchema: json.RawMessage(`null`)})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.HasResponseSchema() {
		t.Fatal("JSON null became a schema and would reject non-Responses streams")
	}
	cfg := Config{Enabled: true, ScanResponses: true}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"response_schema"`) {
		t.Fatal("absent schema serialized into policy")
	}
}
