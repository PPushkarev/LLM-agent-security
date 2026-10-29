package mcpguard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"guard/internal/filter"
)

type fixture struct {
	mu     sync.Mutex
	calls  int
	last   json.RawMessage
	output string
	wait   bool
}

func (f *fixture) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }
func fixtureServer(t *testing.T, f *fixture) *httptest.Server {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	schema := json.RawMessage(`{"type":"object","properties":{"message":{"type":"string"},"repo":{"type":"string"}},"required":["message"],"additionalProperties":false}`)
	for _, name := range []string{"echo", "delete"} {
		s.AddTool(&mcp.Tool{Name: name, InputSchema: schema}, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.mu.Lock()
			f.calls++
			f.last = append([]byte(nil), r.Params.Arguments...)
			output := f.output
			wait := f.wait
			f.mu.Unlock()
			if wait {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			if output == "" {
				output = string(r.Params.Arguments)
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: output}}}, nil
		})
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, PropagateRequestCancellation: true})
	upstream := httptest.NewServer(h)
	t.Cleanup(upstream.Close)
	return upstream
}
func setup(t *testing.T, f *fixture, edit func(*Server)) (*Gateway, *mcp.ClientSession) {
	t.Helper()
	up := fixtureServer(t, f)
	dir := t.TempDir()
	s := Server{URL: up.URL, AllowHTTP: true, Tools: map[string]Tool{"echo": {Action: "allow", Schema: json.RawMessage(`{"type":"object","properties":{"repo":{"const":"allowed"}}}`)}}}
	if edit != nil {
		edit(&s)
	}
	cfg := Config{AuditLog: filepath.Join(dir, "audit.jsonl"), ApprovalDir: filepath.Join(dir, "approvals"), Servers: map[string]Server{"fixture": s}}
	g, err := New(context.Background(), cfg, filter.Config{Enabled: true, Redact: []filter.Rule{{Name: "email", Pattern: `[A-Za-z]+@[A-Za-z]+\.[A-Za-z]+`, Action: "redact"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	server := httptest.NewServer(g)
	t.Cleanup(server.Close)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: &remoteTransport{base: transport, headers: http.Header{"Authorization": []string{"Bearer " + g.Token()}}}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: server.URL + Prefix + "fixture", HTTPClient: client, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return g, cs
}
func TestGatewayAllowlistAndFilters(t *testing.T) {
	f := &fixture{output: "response alice@example.com"}
	g, client := setup(t, f, nil)
	list, err := client.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) != 1 || list.Tools[0].Name != "echo" {
		t.Fatalf("unexpected exposed tools: %+v", list.Tools)
	}
	if _, err := client.CallTool(context.Background(), &mcp.CallToolParams{Name: "delete", Arguments: map[string]any{"message": "x"}}); err == nil {
		t.Fatal("hidden tool could be called")
	}
	for _, tc := range []struct {
		args    json.RawMessage
		allowed bool
	}{
		{json.RawMessage(`{"message":"alice\u0040example.com","repo":"allowed"}`), true},
		{json.RawMessage(`{"message":"x","repo":"other"}`), false},
		{json.RawMessage(`{"message":"x","extra":true}`), false},
		{json.RawMessage(`{"message":"clean","message":"-----BEGIN PRIVATE KEY-----"}`), false},
		{json.RawMessage(`{"message":"-----BEGIN PRIVATE KEY-----"}`), false},
	} {
		result, err := client.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo", Arguments: tc.args})
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError == tc.allowed {
			t.Fatalf("args=%s isError=%v", tc.args, result.IsError)
		}
		if tc.allowed {
			b, _ := json.Marshal(result)
			if strings.Contains(string(b), "alice@example.com") {
				t.Fatal("response email was not filtered")
			}
		}
	}
	if f.count() != 1 {
		t.Fatalf("blocked calls reached upstream: %d", f.count())
	}
	f.mu.Lock()
	last := string(f.last)
	f.mu.Unlock()
	if strings.Contains(last, "alice") || !strings.Contains(last, "REDACTED:email") {
		t.Fatalf("arguments not redacted: %s", last)
	}
	b, err := os.ReadFile(g.cfg.AuditLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "alice") {
		t.Fatal("raw arguments leaked into audit")
	}
	if !strings.Contains(string(b), "call.completed") || !strings.Contains(string(b), "call.blocked") {
		t.Fatal("missing audit events")
	}
}
func TestGatewayApprovals(t *testing.T) {
	for _, approve := range []bool{true, false} {
		t.Run(fmt.Sprint(approve), func(t *testing.T) {
			f := &fixture{}
			g, c := setup(t, f, func(s *Server) { p := s.Tools["echo"]; p.Action = "ask"; s.Tools["echo"] = p })
			done := make(chan *mcp.CallToolResult, 1)
			errs := make(chan error, 1)
			go func() {
				result, err := c.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"message": "hello"}})
				done <- result
				errs <- err
			}()
			var pending []Approval
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				pending, _ = Pending(g.cfg.ApprovalDir)
				if len(pending) > 0 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if len(pending) != 1 {
				t.Fatal("approval request missing")
			}
			if f.count() != 0 {
				t.Fatal("call executed before approval")
			}
			if err := Decide(g.cfg.ApprovalDir, pending[0].ID, approve); err != nil {
				t.Fatal(err)
			}
			select {
			case result := <-done:
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
				if result.IsError == approve {
					t.Fatalf("unexpected result %+v", result)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("approval did not finish")
			}
			if (f.count() == 1) != approve {
				t.Fatal("incorrect upstream call count")
			}
		})
	}
}
func TestGatewayBudgetsAndResults(t *testing.T) {
	f := &fixture{output: strings.Repeat("x", 1000)}
	_, c := setup(t, f, func(s *Server) { s.MaxCalls = 1; s.MaxResponseBytes = 100 })
	for range 2 {
		result, err := c.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"message": "hello"}})
		if err != nil || !result.IsError {
			t.Fatalf("expected denial: %v %+v", err, result)
		}
	}
	if f.count() != 1 {
		t.Fatal("budget bypass")
	}
}
func TestGatewayAuthenticationAndMethods(t *testing.T) {
	g, _ := setup(t, &fixture{}, nil)
	for _, tc := range []struct {
		path, token, origin string
		status              int
	}{
		{Prefix + "fixture", "", "", 401},
		{Prefix + "unknown", g.Token(), "", 404},
		{Prefix + "fixture", g.Token(), "https://evil.example", 403},
	} {
		r := httptest.NewRequest("POST", tc.path, strings.NewReader(`{}`))
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		r.Host = "127.0.0.1:1234"
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("status %d want %d", w.Code, tc.status)
		}
	}
}
func TestGatewayTimeoutRetiresServer(t *testing.T) {
	f := &fixture{wait: true}
	_, c := setup(t, f, func(s *Server) { s.TimeoutSec = 1 })
	for range 2 {
		result, err := c.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"message": "hello"}})
		if err != nil || !result.IsError {
			t.Fatalf("expected error: %v", err)
		}
	}
	if f.count() != 1 {
		t.Fatal("timed out server reused")
	}
}

func TestGatewayAuditFailureStopsCalls(t *testing.T) {
	f := &fixture{}
	g, c := setup(t, f, nil)
	g.audit.file.Close()
	_, err := c.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"message": "hello"}})
	if err == nil {
		t.Fatal("audit failure must fail closed")
	}
	if f.count() != 0 {
		t.Fatal("upstream called without audit")
	}
}
func TestGatewayBlocksOtherMCPMethods(t *testing.T) {
	_, c := setup(t, &fixture{}, nil)
	if _, err := c.ListResources(context.Background(), nil); err == nil {
		t.Fatal("resources unexpectedly exposed")
	}
	if _, err := c.ListPrompts(context.Background(), nil); err == nil {
		t.Fatal("prompts unexpectedly exposed")
	}
}
func TestGatewayRedirectDoesNotForwardCredential(t *testing.T) {
	var mu sync.Mutex
	leaked := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); leaked = true; mu.Unlock() }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer redirect.Close()
	t.Setenv("MCP_TEST_BEARER", "fixture-remote-credential")
	dir := t.TempDir()
	cfg := Config{AuditLog: filepath.Join(dir, "audit"), ApprovalDir: filepath.Join(dir, "approvals"), Servers: map[string]Server{"remote": {URL: redirect.URL, AllowHTTP: true, BearerEnv: "MCP_TEST_BEARER", Tools: map[string]Tool{"echo": {Action: "allow"}}}}}
	if _, err := New(context.Background(), cfg, filter.Config{Enabled: true}, nil); err == nil {
		t.Fatal("redirect accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	if leaked {
		t.Fatal("redirect target was contacted")
	}
}
func TestApprovalDigestAndCancellation(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- requestApproval(ctx, dir, Approval{Session: "test", Server: "server", Tool: "tool", Arguments: json.RawMessage(`{"x":1}`), Deadline: time.Now().Add(5 * time.Second)})
	}()
	var pending []Approval
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pending, _ = Pending(dir)
		if len(pending) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(pending) != 1 {
		t.Fatal("missing pending request")
	}
	b, _ := json.Marshal(decision{Digest: "wrong", Approve: true})
	if err := writeExclusive(filepath.Join(dir, pending[0].ID+".decision"), b); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("wrong approval digest accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("approval didn't finish")
	}
	left, _ := Pending(dir)
	if len(left) != 0 {
		t.Fatal("completed approval not removed")
	}
}

func TestGatewayApprovalCancellation(t *testing.T) {
	f := &fixture{}
	g, c := setup(t, f, func(s *Server) { p := s.Tools["echo"]; p.Action = "ask"; s.Tools["echo"] = p })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"message": "hello"}})
		done <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		pending, _ := Pending(g.cfg.ApprovalDir)
		if len(pending) == 1 {
			found = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		t.Fatal("pending approval missing")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled call succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("call not cancelled")
	}
	for time.Now().Before(deadline) {
		pending, _ := Pending(g.cfg.ApprovalDir)
		if len(pending) == 0 {
			if f.count() != 0 {
				t.Fatal("cancelled call reached upstream")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("cancelled approval remained actionable")
}

func TestFailedStartupCleansLocalResources(t *testing.T) {
	dir := t.TempDir()
	cleaned := false
	cfg := Config{AuditLog: filepath.Join(dir, "audit"), ApprovalDir: filepath.Join(dir, "approvals"), Servers: map[string]Server{"broken": {Command: []string{"/nonexistent-guard-fixture"}, Tools: map[string]Tool{"echo": {Action: "allow"}}}}}
	_, err := New(context.Background(), cfg, filter.Config{Enabled: true}, func(context.Context, string, Server) (*exec.Cmd, func(), error) {
		return exec.Command("/nonexistent-guard-fixture"), func() { cleaned = true }, nil
	})
	if err == nil || !cleaned {
		t.Fatalf("startup failure leaked resources: err=%v cleaned=%t", err, cleaned)
	}
}
