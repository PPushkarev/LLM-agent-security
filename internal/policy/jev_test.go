package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"guard/internal/injection"
	"guard/internal/mcpguard"
)

func TestJevCredentialsStayInParent(t *testing.T) {
	for _, target := range []string{"harness", "mcp", "не настроен ключ в окружении"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			ws := filepath.Join(root, "ws")
			if err := os.Mkdir(ws, 0700); err != nil {
				t.Fatal(err)
			}
			p := Policy{Workspace: ws, PromptInjection: injection.Config{Enabled: true, Provider: "jev", AllowRemote: true, RuntimeDir: filepath.Join(root, "runtime")}}
			if target == "harness" {
				p.EnvAllow = []string{"TYPESAFE_API_KEY"}
			}
			if target == "mcp" {
				p.MCP.Servers = map[string]mcpguard.Server{"example": {EnvAllow: []string{"TYPESAFE_API_KEY"}}}
			}
			body, _ := json.Marshal(p)
			path := filepath.Join(root, "policy.json")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := Load(path)
			if target != "не настроен ключ в окружении" && err == nil {
				t.Fatal("ключ доступен дочернему процессу")
			}
			if target == "не настроен ключ в окружении" {
				if err != nil {
					t.Fatal(err)
				}
				if r.PromptInjection.TokenEnv != "TYPESAFE_API_KEY" {
					t.Fatal("неверная переменная ключа")
				}
			}
		})
	}
}
