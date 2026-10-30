package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"guard/internal/filter"
	"guard/internal/mcpguard"
	"guard/internal/policy"
)

func TestMCPFixtureProcess(t *testing.T) {
	if os.Getenv("GUARD_MCP_FIXTURE") != "guard-mcp-test-process-mode" {
		return
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "local-fixture", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "inspect", InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"},"address":{"type":"string"}},"required":["path","address"],"additionalProperties":false}`)}, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct{ Path, Address string }
		json.Unmarshal(r.Params.Arguments, &a)
		_, readErr := os.ReadFile(a.Path)
		writeErr := os.WriteFile("mcp-unexpected.txt", []byte("escape"), 0600)
		conn, netErr := net.DialTimeout("tcp", a.Address, time.Second)
		if conn != nil {
			conn.Close()
		}
		result := map[string]any{"read_blocked": readErr != nil, "write_blocked": writeErr != nil, "network_blocked": netErr != nil, "model_key_absent": os.Getenv("OPENAI_API_KEY") == ""}
		b, _ := json.Marshal(result)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
	})
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
func TestLocalMCPSandbox(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("OS sandbox")
	}
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	ws := filepath.Join(root, "workspace")
	os.Mkdir(ws, 0700)
	secret := filepath.Join(root, "private.txt")
	os.WriteFile(secret, []byte("must not be readable"), 0600)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARD_MCP_FIXTURE", "guard-mcp-test-process-mode")
	t.Setenv("OPENAI_API_KEY", "fixture-parent-only-key")
	parent := &policy.Resolved{Workspace: ws, Writable: []string{ws}}
	cfg := mcpguard.Config{AuditLog: filepath.Join(root, "audit.jsonl"), ApprovalDir: filepath.Join(root, "approvals"), Servers: map[string]mcpguard.Server{"local": {Command: []string{executable, "-test.run=TestMCPFixtureProcess"}, EnvAllow: []string{"GUARD_MCP_FIXTURE"}, Tools: map[string]mcpguard.Tool{"inspect": {Action: "allow"}}}}}
	gateway, err := mcpguard.New(context.Background(), cfg, filter.Config{Enabled: true}, mcpCommandFactory(parent))
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	endpoint := httptest.NewServer(gateway)
	defer endpoint.Close()
	clientHTTP := &http.Client{Transport: headerTransport{token: gateway.Token()}}
	client, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: endpoint.URL + mcpguard.Prefix + "local", HTTPClient: clientHTTP, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{Name: "inspect", Arguments: map[string]any{"path": secret, "address": endpoint.Listener.Addr().String()}})
	if err != nil || result.IsError {
		t.Fatalf("call failed: %v %+v", err, result)
	}
	content := result.Content[0].(*mcp.TextContent).Text
	var flags map[string]bool
	if err := json.Unmarshal([]byte(content), &flags); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"read_blocked", "write_blocked", "network_blocked", "model_key_absent"} {
		if !flags[name] {
			t.Errorf("local MCP sandbox violation: %s", name)
		}
	}
}

type headerTransport struct{ token string }

func (t headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	return transport.RoundTrip(r)
}
