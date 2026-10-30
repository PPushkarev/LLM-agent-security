package policy

import (
	"encoding/json"
	"guard/internal/filter"
	"guard/internal/guardrails"
	"guard/internal/mcpguard"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictGuardrails(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	ws := filepath.Join(root, "ws")
	os.Mkdir(ws, 0700)
	base := func() *Resolved {
		return &Resolved{Workspace: ws, Writable: []string{ws}, Guardrails: guardrails.Config{Strict: true, MaxSessionSeconds: 60, MaxOutputBytes: 1024, AuditLog: filepath.Join(root, "session.jsonl")}, PromptFilter: filter.Config{Enabled: true, ScanResponses: true, AuditLog: filepath.Join(root, "content.jsonl")}, Limits: Limits{MaxRequests: 10, MaxRequestBytes: 1024}}
	}
	if err := base().validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		change     func(*Resolved)
	}{
		{"disabled", "enforce", func(r *Resolved) { r.PromptFilter.Enabled = false }},
		{"monitor", "enforce", func(r *Resolved) { r.PromptFilter.Mode = "monitor" }},
		{"no response gate", "response scanning", func(r *Resolved) { r.PromptFilter.ScanResponses = false }},
		{"raw network", "raw egress", func(r *Resolved) { r.AllowDomains = []string{"example.com"} }},
		{"no budget", "budgets", func(r *Resolved) { r.Limits.MaxRequests = 0 }},
		{"writable audit", "outside writable", func(r *Resolved) { r.Guardrails.AuditLog = filepath.Join(ws, "audit") }},
		{"no timeout", "positive", func(r *Resolved) { r.Guardrails.MaxSessionSeconds = 0 }},
		{"route without schema", "JSON", func(r *Resolved) { r.KeyInject = []KeyInjection{{Prefix: "/api", Upstream: "https://example.com"}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.change(r)
			if err := r.validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestStrictMCPNoRawEgress(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	ws := filepath.Join(root, "ws")
	os.Mkdir(ws, 0700)
	exe, _ := os.Executable()
	p := Policy{Workspace: ws, Guardrails: guardrails.Config{Strict: true, MaxSessionSeconds: 60, MaxOutputBytes: 1024, AuditLog: filepath.Join(root, "session.jsonl")}, PromptFilter: filter.Config{Enabled: true, ScanResponses: true, AuditLog: filepath.Join(root, "content.jsonl")}, Limits: Limits{MaxRequests: 10, MaxRequestBytes: 1024}, MCP: mcpguard.Config{AuditLog: filepath.Join(root, "mcp.jsonl"), Servers: map[string]mcpguard.Server{"local": {Command: []string{exe}, Sandbox: mcpguard.Sandbox{AllowDomains: []string{"example.com"}}, Tools: map[string]mcpguard.Tool{"echo": {Action: "allow"}}}}}}
	b, _ := json.Marshal(p)
	path := filepath.Join(root, "policy.json")
	os.WriteFile(path, b, 0600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "strict guardrails prohibit raw egress") {
		t.Fatalf("local MCP bypass: %v", err)
	}
}
