package main

import (
	"context"
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
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"guard/internal/filter"
	"guard/internal/mcpguard"
	"guard/internal/policy"
)

func TestCodexManagedMCPEndToEnd(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Seatbelt integration")
	}
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skip("native Codex not installed")
	}
	var mcpCalls atomic.Int32
	backend := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	backend.AddTool(&mcp.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object","properties":{"message":{"type":"string"}},"required":["message"],"additionalProperties":false}`)}, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		mcpCalls.Add(1)
		if strings.Contains(string(r.Params.Arguments), "alice@example.com") {
			t.Error("MCP arguments were not redacted")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "MCP_FIXTURE_OK bob@example.com"}}}, nil
	})
	remote := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return backend }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	defer remote.Close()
	var turns atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		turn := turns.Add(1)
		if strings.Contains(string(body), "bob@example.com") {
			t.Error("MCP result leaked email to model")
		}
		var output any
		if turn == 1 {
			var payload map[string]any
			json.Unmarshal(body, &payload)
			_ = payload
			output = map[string]any{"id": "fc_mcp", "type": "function_call", "call_id": "call_mcp", "name": "echo", "namespace": "mcp__fixture", "arguments": `{"message":"alice@example.com"}`}
		} else {
			if !strings.Contains(string(body), "MCP_FIXTURE_OK") {
				t.Error("MCP tool result not delivered to model")
			}
			output = map[string]any{"id": "msg_final", "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": "GUARD_MCP_OK", "annotations": []any{}}}}
		}
		writeModelEvents(w, output)
	}))
	defer api.Close()
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	ws := filepath.Join(root, "workspace")
	if err := os.Mkdir(ws, 0700); err != nil {
		t.Fatal(err)
	}
	r := &policy.Resolved{Workspace: ws, Writable: []string{ws}, EnvAllow: map[string]bool{"PATH": true}, Raw: policy.Policy{Codex: policy.Codex{Model: "guard-test", Route: "/openai"}}, KeyInject: []policy.KeyInjection{{Prefix: "/openai", Upstream: api.URL, Methods: []string{"POST"}, AllowPaths: []string{"/v1/responses"}, JSON: filter.JSONPolicy{RequireJSON: true}}}, PromptFilter: filter.Config{Enabled: true, Redact: []filter.Rule{{Name: "email", Pattern: `[A-Za-z]+@[A-Za-z]+\.[A-Za-z]+`, Action: "redact"}}}, MCP: mcpguard.Config{AuditLog: filepath.Join(root, "mcp.jsonl"), ApprovalDir: filepath.Join(root, "approvals"), Servers: map[string]mcpguard.Server{"fixture": {URL: remote.URL, AllowHTTP: true, Tools: map[string]mcpguard.Tool{"echo": {Action: "allow"}}}}}}
	if err := runLaunch(r, false, []string{"exec", "--skip-git-repo-check", "--ephemeral", "Use the fixture MCP echo tool once, then answer GUARD_MCP_OK. Do not run shell commands."}, strings.NewReader(""), true); err != nil {
		t.Fatal(err)
	}
	if mcpCalls.Load() != 1 {
		t.Fatalf("managed MCP call count %d, want 1", mcpCalls.Load())
	}
}
func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func writeModelEvents(w http.ResponseWriter, item any) {
	w.Header().Set("Content-Type", "text/event-stream")
	event := func(name string, data any) { fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, mustJSON(data)) }
	event("response.created", map[string]any{"type": "response.created", "response": map[string]any{"id": "resp_fixture", "status": "in_progress", "output": []any{}}})
	event("response.output_item.done", map[string]any{"type": "response.output_item.done", "output_index": 0, "item": item})
	event("response.completed", map[string]any{"type": "response.completed", "response": map[string]any{"id": "resp_fixture", "object": "response", "created_at": 1700000000, "status": "completed", "model": "guard-test", "output": []any{item}, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}})
}
