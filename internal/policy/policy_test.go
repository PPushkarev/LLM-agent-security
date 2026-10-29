package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"guard/internal/credential"
	"guard/internal/filter"
)

func TestPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Policy)
		bad  bool
	}{
		{"valid", func(p *Policy) {}, false},
		{"subscription wrong origin", func(p *Policy) {
			p.KeyInject[0].Env = ""
			p.KeyInject[0].Header = ""
			p.KeyInject[0].Auth = credential.Config{Type: "codex"}
		}, true},
		{"subscription writable cache", func(p *Policy) {
			p.KeyInject[0].Upstream = "https://chatgpt.com"
			p.KeyInject[0].Env = ""
			p.KeyInject[0].Header = ""
			p.KeyInject[0].Auth = credential.Config{Type: "codex", CodexHome: p.Workspace}
		}, true},
		{"negative limit", func(p *Policy) { p.Limits.MaxRequests = -1 }, true},
		{"invalid port", func(p *Policy) { p.ProxyPort = 65536 }, true},
		{"mode typo", func(p *Policy) { p.PromptFilter.Mode = "enfore" }, true},
		{"action typo", func(p *Policy) { p.PromptFilter.Block = []filter.Rule{{Pattern: "x", Action: "blcok"}} }, true},
		{"exposed key", func(p *Policy) { p.EnvAllow = []string{"OPENAI_API_KEY"} }, true},
		{"bad upstream", func(p *Policy) { p.KeyInject[0].Upstream = "file:///etc/passwd" }, true},
		{"duplicate route", func(p *Policy) { p.KeyInject = append(p.KeyInject, p.KeyInject[0]) }, true},
		{"nested route", func(p *Policy) { r := p.KeyInject[0]; r.Prefix = "/api/nested"; p.KeyInject = append(p.KeyInject, r) }, true},
		{"writable audit", func(p *Policy) { p.PromptFilter.AuditLog = filepath.Join(p.Workspace, "audit.log") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ws := filepath.Join(dir, "ws")
			if err := os.Mkdir(ws, 0700); err != nil {
				t.Fatal(err)
			}
			p := Policy{Workspace: ws, PromptFilter: filter.Config{Enabled: true}, KeyInject: []KeyInjection{{Prefix: "/api", Upstream: "https://api.example.com", Env: "OPENAI_API_KEY", Header: "Authorization"}}}
			tc.edit(&p)
			b, _ := json.Marshal(p)
			path := filepath.Join(dir, "policy.json")
			os.WriteFile(path, b, 0600)
			_, err := Load(path)
			if (err != nil) != tc.bad {
				t.Fatalf("error=%v want bad=%t", err, tc.bad)
			}
		})
	}
}
func TestAuditSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	ws := filepath.Join(dir, "ws")
	os.Mkdir(ws, 0700)
	link := filepath.Join(dir, "looks-outside")
	if err := os.Symlink(ws, link); err != nil {
		t.Fatal(err)
	}
	p := Policy{Workspace: ws, PromptFilter: filter.Config{Enabled: true, AuditLog: filepath.Join(link, "audit.log")}}
	b, _ := json.Marshal(p)
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, b, 0600)
	if _, err := Load(path); err == nil {
		t.Fatal("writable audit accepted through symlink")
	}
}
