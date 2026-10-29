package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"guard/internal/credential"
	"guard/internal/filter"
	"guard/internal/policy"
)

func TestCodexEndToEnd(t *testing.T) {
	t.Run("api", func(t *testing.T) { testCodexEndToEnd(t, false) })
	t.Run("chatgpt", func(t *testing.T) { testCodexEndToEnd(t, true) })
}
func testCodexEndToEnd(t *testing.T, subscription bool) {
	if runtime.GOOS != "darwin" {
		t.Skip("Seatbelt integration test")
	}
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skip("Codex CLI not installed")
	}
	t.Setenv("OPENAI_API_KEY", "guard-test-credential")
	var mu sync.Mutex
	var seen int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		seen++
		mu.Unlock()
		expectedPath := "/v1/responses"
		if subscription {
			expectedPath = "/backend-api/codex/responses"
			if r.Header.Get("ChatGPT-Account-ID") != "fixture-account" {
				t.Error("account header not injected")
			}
		}
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected endpoint %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer guard-test-credential" {
			t.Error("proxy did not inject credential")
		}
		if strings.Contains(string(body), "alice@example.com") {
			t.Error("email reached upstream")
		}
		if !strings.Contains(string(body), "REDACTED:email") {
			t.Error("redaction missing from real Codex request")
		}
		if seen > 1 {
			var payload struct {
				Input []map[string]any `json:"input"`
			}
			_ = json.Unmarshal(body, &payload)
			for _, item := range payload.Input {
				if item["type"] == "function_call_output" {
					t.Logf("tool output: %v", item["output"])
				}
			}
		}
		if !json.Valid(body) {
			t.Error("redaction corrupted JSON")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		response := map[string]any{"id": "resp_guard_test", "object": "response", "created_at": 1700000000, "status": "completed", "model": "guard-test", "output": []any{map[string]any{"id": "msg_test", "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": "GUARD_SMOKE_OK", "annotations": []any{}}}}}, "usage": map[string]any{"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
		event := func(name string, v any) { b, _ := json.Marshal(v); fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, b) }
		mu.Lock()
		first := seen == 1
		mu.Unlock()
		if first {
			tool := map[string]any{"id": "fc_guard", "type": "function_call", "call_id": "call_guard", "name": "exec_command", "arguments": `{"cmd":"test -z \"$OPENAI_API_KEY\" && test ! -r secret.txt && ! touch ../guard-escape && printf tool-ok > guard-tool.txt","max_output_tokens":100}`}
			response["output"] = []any{tool}
		}
		event("response.created", map[string]any{"type": "response.created", "response": map[string]any{"id": "resp_guard_test", "status": "in_progress", "output": []any{}}})
		item := response["output"].([]any)[0]
		event("response.output_item.added", map[string]any{"type": "response.output_item.added", "output_index": 0, "item": map[string]any{"id": "msg_test", "type": "message", "role": "assistant", "content": []any{}}})
		event("response.output_text.delta", map[string]any{"type": "response.output_text.delta", "item_id": "msg_test", "output_index": 0, "content_index": 0, "delta": "GUARD_SMOKE_OK"})
		event("response.output_item.done", map[string]any{"type": "response.output_item.done", "output_index": 0, "item": item})
		event("response.completed", map[string]any{"type": "response.completed", "response": response})
	}))
	defer up.Close()
	ws := t.TempDir()
	ws, _ = filepath.EvalSymlinks(ws)
	r := &policy.Resolved{Workspace: ws, Writable: []string{ws}, EnvAllow: map[string]bool{"PATH": true}, Raw: policy.Policy{Codex: policy.Codex{Model: "guard-test", Route: "/openai"}}, KeyInject: []policy.KeyInjection{{Prefix: "/openai", Upstream: up.URL, Env: "OPENAI_API_KEY", Header: "Authorization", HeaderPrefix: "Bearer ", Methods: []string{"POST"}, AllowPaths: []string{"/v1/responses"}, JSON: filter.JSONPolicy{RequireJSON: true, AllowModels: []string{"guard-test"}}}}, PromptFilter: filter.Config{Enabled: true, Redact: []filter.Rule{{Name: "email", Pattern: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, Action: "redact"}}}}
	if subscription {
		authHome := t.TempDir()
		cache := `{"tokens":{"access_token":"guard-test-credential","account_id":"fixture-account","refresh_token":"fixture-refresh"}}`
		if err := os.WriteFile(filepath.Join(authHome, "auth.json"), []byte(cache), 0600); err != nil {
			t.Fatal(err)
		}
		rt := &r.KeyInject[0]
		rt.Auth = credential.Config{Type: "codex", CodexHome: authHome}
		rt.Env, rt.Header, rt.HeaderPrefix = "", "", ""
		rt.AllowPaths = []string{"/backend-api/codex/responses"}
	}
	secret := filepath.Join(ws, "secret.txt")
	if err := os.WriteFile(secret, []byte("fixture-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	r.ReadDeny = append(r.ReadDeny, secret)
	output := filepath.Join(ws, "last.txt")
	err := runLaunch(r, false, []string{"exec", "--skip-git-repo-check", "--ephemeral", "-o", output, "Say hello to alice@example.com."}, strings.NewReader(""), true)
	if err != nil {
		t.Fatalf("real Codex under guard: %v", err)
	}
	b, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != "GUARD_SMOKE_OK" {
		t.Fatalf("unexpected Codex output %q", b)
	}
	toolOutput, err := os.ReadFile(filepath.Join(ws, "guard-tool.txt"))
	if err != nil || string(toolOutput) != "tool-ok" {
		t.Fatalf("Codex tool execution failed: %q %v", toolOutput, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen != 2 {
		t.Fatalf("API requests: %d, want 2", seen)
	}
}
