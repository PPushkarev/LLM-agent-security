package main

import (
	"context"
	"encoding/json"
	"fmt"
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

// The fixture is an independent harness, with no Codex installation or API.
func TestGenericHarnessProcess(t *testing.T) {
	mode := os.Getenv("GUARD_HARNESS_FIXTURE")
	if mode == "" {
		return
	}
	if mode == "bridge" {
		if err := runMCPBridge(context.Background(), os.Getenv("GUARD_MCP_CONFIG"), "fixture"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	err := func() error {
		ctx := context.Background()
		var transport mcp.Transport
		if mode == "stdio" {
			executable, _ := os.Executable()
			cmd := exec.Command(executable, "-test.run=^TestGenericHarnessProcess$")
			cmd.Env = overrideEnv(os.Environ(), []string{"GUARD_HARNESS_FIXTURE=bridge"})
			transport = &mcp.CommandTransport{Command: cmd}
		} else {
			b, err := os.ReadFile(os.Getenv("GUARD_MCP_CONFIG"))
			if err != nil {
				return err
			}
			var cfg MCPConnections
			if err := json.Unmarshal(b, &cfg); err != nil {
				return err
			}
			c := cfg.Servers["fixture"]
			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.Proxy = nil
			transport = &mcp.StreamableClientTransport{Endpoint: c.URL, HTTPClient: &http.Client{Transport: mcpHeaderTransport{tr, c.Headers}}, DisableStandaloneSSE: true, MaxRetries: -1}
		}
		session, err := mcp.NewClient(&mcp.Implementation{Name: "independent-harness", Version: "1"}, nil).Connect(ctx, transport, nil)
		if err != nil {
			return err
		}
		defer session.Close()
		tools, err := session.ListTools(ctx, &mcp.ListToolsParams{})
		if err != nil {
			return err
		}
		if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo" {
			return fmt.Errorf("unexpected tools: %v", tools)
		}
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"message": "alice@example.com"}})
		if err != nil {
			return err
		}
		b, _ := json.Marshal(result)
		if result.IsError || !strings.Contains(string(b), "FIXTURE_OK") || strings.Contains(string(b), "bob@example.com") {
			return fmt.Errorf("unexpected result: %s", b)
		}
		denied, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "hidden", Arguments: map[string]any{}})
		if err == nil && !denied.IsError {
			return fmt.Errorf("hidden tool was allowed")
		}
		return nil
	}()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
func TestGenericHarnessManagedMCP(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Seatbelt integration")
	}
	for _, mode := range []string{"http", "stdio"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			backend := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
			backend.AddTool(&mcp.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object","properties":{"message":{"type":"string"}},"required":["message"]}`)}, func(_ context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				calls.Add(1)
				if strings.Contains(string(r.Params.Arguments), "alice@example.com") {
					t.Error("unfiltered arguments")
				}
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "FIXTURE_OK bob@example.com"}}}, nil
			})
			remote := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return backend }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
			defer remote.Close()
			root, _ := filepath.EvalSymlinks(t.TempDir())
			ws := filepath.Join(root, "workspace")
			if err := os.Mkdir(ws, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GUARD_HARNESS_FIXTURE", mode)
			r := &policy.Resolved{Workspace: ws, Writable: []string{ws}, EnvAllow: map[string]bool{"GUARD_HARNESS_FIXTURE": true}, PromptFilter: filter.Config{Enabled: true, Redact: []filter.Rule{{Name: "email", Pattern: `[A-Za-z]+@[A-Za-z]+\.[A-Za-z]+`, Action: "redact"}}}, MCP: mcpguard.Config{AuditLog: filepath.Join(root, "audit.jsonl"), ApprovalDir: filepath.Join(root, "approvals"), Servers: map[string]mcpguard.Server{"fixture": {URL: remote.URL, AllowHTTP: true, Tools: map[string]mcpguard.Tool{"echo": {Action: "allow"}}}}}}
			executable, _ := os.Executable()
			if err := runLaunch(r, false, []string{executable, "-test.run=^TestGenericHarnessProcess$"}, strings.NewReader(""), false); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatalf("backend calls=%d", calls.Load())
			}
		})
	}
}
