package policy

import (
	"encoding/json"
	"guard/internal/injection"
	"guard/internal/mcpguard"
	"os"
	"path/filepath"
	"testing"
)

func TestInjectionPolicyBoundary(t *testing.T) {
	for _, mode := range []string{"valid", "writable runtime", "token to harness", "token to MCP", "missing required detector", "flag required detector"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			ws := filepath.Join(root, "ws")
			os.Mkdir(ws, 0700)
			p := Policy{Workspace: ws, PromptInjection: injection.Config{Enabled: true, Endpoint: "http://127.0.0.1:8766/scan", RuntimeDir: filepath.Join(root, "classifier")}}
			switch mode {
			case "writable runtime":
				p.PromptInjection.RuntimeDir = filepath.Join(ws, "classifier")
			case "token to harness":
				p.EnvAllow = []string{"GUARD_INJECTION_TOKEN"}
			case "token to MCP":
				p.MCP.Servers = map[string]mcpguard.Server{"local": {EnvAllow: []string{"GUARD_INJECTION_TOKEN"}}}
			case "missing required detector":
				p.Guardrails.RequirePromptInjection = true
				p.PromptInjection.Enabled = false
			case "flag required detector":
				p.Guardrails.RequirePromptInjection = true
				p.PromptInjection.Action = "flag"
			}
			b, _ := json.Marshal(p)
			path := filepath.Join(root, "policy.json")
			os.WriteFile(path, b, 0600)
			r, err := Load(path)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("%s: %v", mode, err)
			}
			if mode == "valid" && len(r.ReadDeny) == 0 {
				t.Fatal("classifier runtime was not protected")
			}
		})
	}
}
