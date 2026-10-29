package filter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONContentFiltering(t *testing.T) {
	f, err := New(Config{Enabled: true, Redact: []Rule{{Name: "email", Pattern: `[A-Za-z]+@[A-Za-z]+\.[A-Za-z]+`, Action: "redact"}}})
	if err != nil {
		t.Fatal(err)
	}
	j, err := NewJSON(JSONPolicy{RequireJSON: true, AllowModels: []string{"approved"}, DenyFields: []string{"/metadata/private"}, Rules: []JSONRule{{Name: "customer", Path: "/input/*/content/*/text", Pattern: "Acme", Action: "redact"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body string
		action     Action
		rule       string
	}{
		{"unicode escape", `{"model":"approved","input":[{"content":[{"text":"alice\u0040example.com Acme"}]}]}`, Redact, ""},
		{"wrong model", `{"model":"other","input":[]}`, Block, "model_not_allowed"},
		{"missing model", `{"input":[]}`, Block, "model_not_allowed"},
		{"forbidden field", `{"model":"approved","metadata":{"private":null}}`, Block, "forbidden_json_field:/metadata/private"},
		{"encoded key", `{"model":"approved","metadata":{"\u0070rivate":true}}`, Block, "forbidden_json_field:/metadata/private"},
		{"invalid", `{broken`, Block, "invalid_json"},
		{"duplicate key", `{"model":"other","model":"approved"}`, Block, "invalid_json"},
		{"multiple documents", `{} {}`, Block, "invalid_json"},
		{"clean", `{ "model": "approved", "input": "hello" }`, Allow, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, d := j.Request([]byte(tc.body), f)
			if d.Action != tc.action {
				t.Fatalf("decision %+v", d)
			}
			if tc.rule != "" && d.Rule != tc.rule {
				t.Fatalf("rule %q want %q", d.Rule, tc.rule)
			}
			if d.Action == Redact {
				if !json.Valid(out) || strings.Contains(string(out), "Acme") || strings.Contains(string(out), "example.com") {
					t.Fatalf("unsafe output %s", out)
				}
			}
			if d.Action == Allow && string(out) != tc.body {
				t.Fatalf("clean JSON changed: %s", out)
			}
		})
	}
}
func TestJSONBlockBeforeRedaction(t *testing.T) {
	f, _ := New(Config{Enabled: true})
	j, _ := NewJSON(JSONPolicy{Rules: []JSONRule{{Name: "redact", Path: "/value", Pattern: "secret", Action: "redact"}, {Name: "block", Path: "/value", Pattern: "secret", Action: "block"}}})
	_, d := j.Request([]byte(`{"value":"secret"}`), f)
	if d.Action != Block {
		t.Fatalf("redaction hid blocking match: %+v", d)
	}
}
func TestJSONMonitorAndSecret(t *testing.T) {
	f, _ := New(Config{Enabled: true, Mode: "monitor", Redact: []Rule{{Name: "value", Pattern: "sensitive", Action: "redact"}}})
	j, _ := NewJSON(JSONPolicy{RequireJSON: true})
	body := []byte(`{"text":"\u0073ensitive"}`)
	out, d := j.Request(body, f)
	if string(out) != string(body) || d.Action != Allow || !d.Monitored {
		t.Fatalf("monitor changed request: %s %+v", out, d)
	}
	f, _ = New(Config{Enabled: true})
	f.ProtectSecret("arbitrary-credential")
	_, d = j.Request([]byte(`{"text":"arbitrary\u002dcredential"}`), f)
	if d.Action != Block {
		t.Fatal("escaped actual credential leaked")
	}
}

func TestJSONConstraintsRequireValidJSON(t *testing.T) {
	f, _ := New(Config{})
	j, _ := NewJSON(JSONPolicy{AllowModels: []string{"approved"}})
	_, d := j.Request([]byte("not json"), f)
	if d.Action != Block {
		t.Fatal("malformed body bypassed model policy")
	}
}
