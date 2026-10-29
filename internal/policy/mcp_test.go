package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"guard/internal/filter"
	"guard/internal/mcpguard"
)

func TestMCPPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Policy)
		bad  bool
	}{
		{"valid", func(p *Policy) {}, false},
		{"writable audit", func(p *Policy) { p.MCP.AuditLog = filepath.Join(p.Workspace, "audit") }, true},
		{"writable approvals", func(p *Policy) { p.MCP.ApprovalDir = filepath.Join(p.Workspace, "approvals") }, true},
		{"unknown decision", func(p *Policy) {
			s := p.MCP.Servers["docs"]
			s.Tools["search"] = mcpguard.Tool{Action: "alow"}
			p.MCP.Servers["docs"] = s
		}, true},
		{"raw egress bypass", func(p *Policy) { p.AllowDomains = []string{"mcp.example.com"} }, true},
		{"insecure remote", func(p *Policy) {
			s := p.MCP.Servers["docs"]
			s.URL = "http://mcp.example.com/mcp"
			s.AllowHTTP = true
			p.MCP.Servers["docs"] = s
		}, true},
		{"invalid pointer", func(p *Policy) {
			s := p.MCP.Servers["docs"]
			s.Tools["search"] = mcpguard.Tool{Action: "allow", Arguments: filter.JSONPolicy{DenyFields: []string{"missing/slash"}}}
			p.MCP.Servers["docs"] = s
		}, true},
		{"schema remote ref", func(p *Policy) {
			s := p.MCP.Servers["docs"]
			s.Tools["search"] = mcpguard.Tool{Action: "allow", Schema: json.RawMessage(`{"$ref":"https://example.com/schema"}`)}
			p.MCP.Servers["docs"] = s
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			ws := filepath.Join(root, "ws")
			os.Mkdir(ws, 0700)
			p := Policy{Workspace: ws, PromptFilter: filter.Config{Enabled: true}, MCP: mcpguard.Config{AuditLog: filepath.Join(root, "mcp.jsonl"), Servers: map[string]mcpguard.Server{"docs": {URL: "https://mcp.example.com/mcp", Tools: map[string]mcpguard.Tool{"search": {Action: "allow"}}}}}}
			tc.edit(&p)
			b, _ := json.Marshal(p)
			path := filepath.Join(root, "policy.json")
			os.WriteFile(path, b, 0600)
			r, err := Load(path)
			if (err != nil) != tc.bad {
				t.Fatalf("err=%v bad=%t", err, tc.bad)
			}
			if !tc.bad && r.MCP.ApprovalDir == "" {
				t.Fatal("approval directory not resolved")
			}
		})
	}
}
