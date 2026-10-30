package mcpguard

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"guard/internal/filter"
	"guard/internal/injection"
)

type CommandFactory func(context.Context, string, Server) (*exec.Cmd, func(), error)
type Gateway struct {
	detector *injection.Detector
	cfg      Config
	audit    *audit
	token    string
	ctx      context.Context
	cancel   context.CancelFunc
	servers  map[string]*managed
	once     sync.Once
	requests sync.Map
}
type managed struct {
	name               string
	cfg                Server
	session            *mcp.ClientSession
	handler            http.Handler
	filter             *filter.Filter
	slots              chan struct{}
	mu                 sync.Mutex
	calls, windowCalls int
	window             time.Time
	retired            bool
	cleanup            func()
	closeOnce          sync.Once
}

// New initializes and pins each allowed server's catalog before exposing it.
func New(ctx context.Context, cfg Config, content filter.Config, factory CommandFactory) (g *Gateway, err error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	if len(cfg.Servers) == 0 {
		return nil, nil
	}
	a, err := newAudit(cfg.AuditLog)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	g = &Gateway{cfg: cfg, audit: a, token: randomID() + randomID(), ctx: ctx, cancel: cancel, servers: map[string]*managed{}}
	success := false
	defer func(gateway *Gateway) {
		if !success {
			gateway.Close()
		}
	}(g)
	if err = os.MkdirAll(cfg.ApprovalDir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(cfg.ApprovalDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("MCP approval directory must be private (0700)")
	}
	g.detector, err = injection.New(cfg.Injection)
	if err != nil {
		return nil, err
	}
	for name, raw := range cfg.Servers {
		s := defaults(raw)
		content.AuditLog = ""
		f, e := filter.New(content)
		if e != nil {
			return nil, e
		}
		if cfg.Injection.Enabled {
			f.ProtectSecret(os.Getenv(cfg.Injection.Defaults().TokenEnv))
		}
		m := &managed{name: name, cfg: s, filter: f, slots: make(chan struct{}, s.MaxParallel), window: time.Now()}
		g.servers[name] = m
		var transport mcp.Transport
		if s.URL != "" {
			headers := http.Header{}
			if s.BearerEnv != "" {
				secret := os.Getenv(s.BearerEnv)
				if secret == "" {
					return nil, fmt.Errorf("MCP %s: required bearer environment variable is empty", name)
				}
				headers.Set("Authorization", "Bearer "+secret)
				f.ProtectSecret(secret)
			}
			transportHTTP := http.DefaultTransport.(*http.Transport).Clone()
			transportHTTP.Proxy = nil
			m.cleanup = transportHTTP.CloseIdleConnections
			client := &http.Client{Transport: &remoteTransport{base: transportHTTP, headers: headers}, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("MCP redirects are disabled") }}
			transport = &mcp.StreamableClientTransport{Endpoint: s.URL, HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true, MaxEventSize: maxBytes}
		} else {
			if factory == nil {
				return nil, fmt.Errorf("MCP local command factory is unavailable")
			}
			cmd, cleanup, e := factory(ctx, name, s)
			if e != nil {
				return nil, e
			}
			m.cleanup = cleanup
			for _, variable := range s.EnvAllow {
				f.ProtectSecret(os.Getenv(variable))
			}
			// SDK caps inbound stdio JSON-RPC frames at 16 MiB, even for a malicious server.
			transport = &mcp.CommandTransport{Command: cmd, TerminateDuration: time.Second}
		}
		connectCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		client := mcp.NewClient(&mcp.Implementation{Name: "guard-mcp", Version: "1"}, nil)
		session, e := client.Connect(connectCtx, transport, nil)
		if e != nil {
			stop()
			return nil, fmt.Errorf("MCP %s initialization failed", name)
		}
		m.session = session
		frontend := mcp.NewServer(&mcp.Implementation{Name: "guard-" + name, Version: "1"}, nil)
		frontend.AddReceivingMiddleware(g.methods(m))
		catalog := map[string]bool{}
		count := 0
		catalogBytes := 0
		for tool, e := range session.Tools(connectCtx, nil) {
			if e != nil {
				stop()
				return nil, fmt.Errorf("MCP %s catalog unavailable", name)
			}
			count++
			if count > 256 {
				stop()
				return nil, fmt.Errorf("MCP %s catalog exceeds 256 tools", name)
			}
			tp, exists := s.Tools[tool.Name]
			if !exists || tp.Action == "deny" || tp.Action == "" {
				continue
			}
			if catalog[tool.Name] {
				stop()
				return nil, fmt.Errorf("MCP %s returned a duplicate tool", name)
			}
			catalog[tool.Name] = true
			schemaBytes, e := json.Marshal(tool.InputSchema)
			if e != nil {
				stop()
				return nil, fmt.Errorf("invalid MCP input schema")
			}
			if len(schemaBytes) > 256<<10 {
				stop()
				return nil, fmt.Errorf("MCP %s/%s input schema exceeds 256 KiB", name, tool.Name)
			}
			catalogBytes += len(schemaBytes)
			var object map[string]any
			if json.Unmarshal(schemaBytes, &object) != nil || object["type"] != "object" {
				stop()
				return nil, fmt.Errorf("MCP %s/%s needs an object input schema", name, tool.Name)
			}
			metadataFilter, _ := filter.NewJSON(filter.JSONPolicy{RequireJSON: true})
			_, metadataDecision := metadataFilter.Request(schemaBytes, f)
			if metadataDecision.Action != filter.Allow {
				stop()
				return nil, fmt.Errorf("MCP %s/%s schema contains filtered content", name, tool.Name)
			}
			input, e := compileSchema(schemaBytes)
			if e != nil {
				stop()
				return nil, fmt.Errorf("MCP %s/%s: unsupported input schema", name, tool.Name)
			}
			extra, e := compileSchema(tp.Schema)
			if e != nil {
				stop()
				return nil, e
			}
			outputBytes, _ := json.Marshal(tool.OutputSchema)
			catalogBytes += len(outputBytes)
			if len(outputBytes) > 256<<10 || catalogBytes > 4<<20 {
				stop()
				return nil, fmt.Errorf("MCP %s schema catalog exceeds metadata limits", name)
			}
			var output *jsonschema.Resolved
			if tool.OutputSchema != nil {
				_, metadataDecision = metadataFilter.Request(outputBytes, f)
				if metadataDecision.Action != filter.Allow {
					stop()
					return nil, fmt.Errorf("MCP %s/%s output schema contains filtered content", name, tool.Name)
				}
				output, e = compileSchema(outputBytes)
				if e != nil {
					stop()
					return nil, fmt.Errorf("MCP %s/%s: unsupported output schema", name, tool.Name)
				}
			}
			argsPolicy := tp.Arguments
			argsPolicy.RequireJSON = true
			args, _ := filter.NewJSON(argsPolicy)
			resultPolicy := tp.Result
			resultPolicy.RequireJSON = true
			result, _ := filter.NewJSON(resultPolicy)
			description := fmt.Sprintf("Guard-managed tool %s from %s. Server policies apply.", tool.Name, name)
			exposed := &mcp.Tool{Name: tool.Name, Description: description, InputSchema: tool.InputSchema, OutputSchema: tool.OutputSchema}
			frontend.AddTool(exposed, g.call(m, tool.Name, tp, args, result, input, extra, output))
			if e := g.audit.write(event{Type: "tool.pinned", Server: name, Tool: tool.Name, SchemaHash: digest(schemaBytes)}); e != nil {
				stop()
				return nil, e
			}
		}
		stop()
		for tool, tp := range s.Tools {
			if tp.Action != "deny" && tp.Action != "" && !catalog[tool] {
				return nil, fmt.Errorf("MCP %s: allowed tool %s is not available", name, tool)
			}
		}
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return frontend }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: int64(s.MaxRequestBytes + 4096), PropagateRequestCancellation: true})
		m.handler = http.NewCrossOriginProtection().Handler(handler)
	}
	if err = g.audit.write(event{Type: "gateway.started"}); err != nil {
		return nil, err
	}
	success = true
	return g, nil
}
func (g *Gateway) Token() string { return g.token }
func (g *Gateway) Close() {
	if g != nil {
		g.detector.Close()
	}
	if g == nil {
		return
	}
	g.once.Do(func() {
		g.cancel()
		for _, m := range g.servers {
			m.close()
		}
		g.audit.write(event{Type: "gateway.closed"})
		g.audit.close()
	})
}
func (m *managed) close() {
	m.closeOnce.Do(func() {
		if m.session != nil {
			m.session.Close()
		}
		if m.cleanup != nil {
			m.cleanup()
		}
		m.filter.Close()
	})
}
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.IsAbs() || !strings.HasPrefix(r.URL.Path, Prefix) {
		http.Error(w, "invalid MCP endpoint", 400)
		return
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		http.Error(w, "invalid host", 403)
		return
	}
	supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(supplied), []byte(g.token)) != 1 {
		http.Error(w, "MCP gateway authentication required", 401)
		return
	}
	if r.Header.Get("Origin") != "" {
		http.Error(w, "browser origins are disabled", 403)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, Prefix)
	m, ok := g.servers[name]
	if !ok {
		g.audit.write(event{Type: "server.denied", Server: name, Decision: "deny"})
		http.NotFound(w, r)
		return
	}
	if e := r.Header.Get("Content-Encoding"); e != "" && !strings.EqualFold(e, "identity") {
		http.Error(w, "encoded MCP bodies are disabled", 415)
		return
	}
	select {
	case <-g.ctx.Done():
		http.Error(w, "gateway closed", 503)
		return
	default:
	}
	requestID := randomID()
	g.requests.Store(requestID, r.Context())
	defer g.requests.Delete(requestID)
	r = r.Clone(r.Context())
	r.Header.Set("X-Guard-Request-ID", requestID)
	m.handler.ServeHTTP(w, r)
}
func (g *Gateway) methods(m *managed) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case "initialize", "server/discover", "ping", "tools/list", "tools/call", "notifications/initialized", "notifications/cancelled":
			default:
				if err := g.audit.write(event{Type: "method.denied", Server: m.name, Rule: method, Decision: "deny"}); err != nil {
					return nil, fmt.Errorf("MCP audit unavailable")
				}
				return nil, fmt.Errorf("MCP method is not allowed")
			}
			result, err := next(ctx, method, req)
			if method == "tools/call" && err != nil {
				if e := g.audit.write(event{Type: "call.rejected", Server: m.name, Tool: callName(req), Decision: "deny", Rule: "unknown_tool_or_invalid_protocol"}); e != nil {
					return nil, fmt.Errorf("MCP audit unavailable")
				}
			}
			return result, err
		}
	}
}
func (m *managed) admit() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if time.Since(m.window) >= time.Minute {
		m.window = time.Now()
		m.windowCalls = 0
	}
	if m.retired || m.calls >= m.cfg.MaxCalls || m.windowCalls >= m.cfg.RatePerMin {
		return false
	}
	m.calls++
	m.windowCalls++
	return true
}
func toolError(reason string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "guard MCP: " + reason}}}
}
func (g *Gateway) call(m *managed, name string, tp Tool, argsFilter, resultFilter *filter.JSONFilter, input, extra, output *jsonschema.Resolved) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(g.ctx, cancel)
		defer stop()
		if req.Extra == nil {
			return nil, fmt.Errorf("MCP request context missing")
		}
		value, ok := g.requests.Load(req.Extra.Header.Get("X-Guard-Request-ID"))
		if !ok {
			return nil, fmt.Errorf("MCP request context missing")
		}
		httpContext := value.(context.Context)
		if httpContext.Err() != nil {
			cancel()
		}
		stopHTTP := context.AfterFunc(httpContext, cancel)
		defer stopHTTP()
		id := randomID()
		started := time.Now()
		reject := func(reason string) (*mcp.CallToolResult, error) {
			if err := g.audit.write(event{Type: "call.blocked", ID: id, Server: m.name, Tool: name, Decision: "deny", Rule: reason}); err != nil {
				return nil, fmt.Errorf("MCP audit unavailable")
			}
			return toolError(reason), nil
		}
		raw := req.Params.Arguments
		if len(raw) == 0 {
			raw = json.RawMessage(`{}`)
		}
		if len(raw) > m.cfg.MaxRequestBytes {
			return reject("request_too_large")
		}
		if !isObject(raw) {
			return reject("arguments_must_be_object")
		}
		body, d := argsFilter.Request(raw, m.filter)
		if d.Action == filter.Block {
			return reject("arguments:" + d.Rule)
		}

		if schemaValue(input, body) != nil || schemaValue(extra, body) != nil {
			return reject("arguments_schema")
		}
		// No caller-supplied metadata, roots, inputResponses or opaque requestState is forwarded.
		select {
		case m.slots <- struct{}{}:
			defer func() { <-m.slots }()
		default:
			return reject("parallel_limit")
		}
		if !m.admit() {
			return reject("call_or_rate_limit")
		}
		if verdict := g.detector.Scan(ctx, "mcp_arguments", body); verdict.Model != "" {
			decision := "allow"
			if verdict.Block {
				decision = "deny"
			} else if verdict.Flag {
				decision = "flag"
			}
			if err := g.audit.write(event{Type: "injection.scanned", ID: id, Server: m.name, Tool: name, Decision: decision, Rule: verdict.Rule, Model: verdict.Model, Score: verdict.Score, ArgumentsHash: verdict.Hash}); err != nil {
				return nil, fmt.Errorf("MCP audit unavailable")
			}
			if verdict.Block {
				return reject(verdict.Rule)
			}
		}
		e := event{Type: "call.allowed", ID: id, Server: m.name, Tool: name, Decision: tp.Action, ArgumentsHash: digest(body)}
		if err := g.audit.write(e); err != nil {
			return nil, fmt.Errorf("MCP audit unavailable")
		}
		if tp.Action == "ask" {
			deadline := time.Now().Add(time.Duration(m.cfg.ApprovalTimeoutSec) * time.Second)
			if err := requestApproval(ctx, g.cfg.ApprovalDir, Approval{CallID: id, Session: g.audit.session, Server: m.name, Tool: name, Arguments: body, Deadline: deadline}); err != nil {
				return reject("approval_not_granted")
			}
			if err := g.audit.write(event{Type: "call.approved", ID: id, Server: m.name, Tool: name, Decision: "allow", ArgumentsHash: digest(body)}); err != nil {
				return nil, fmt.Errorf("MCP audit unavailable")
			}
		}
		if ctx.Err() != nil {
			return reject("request_cancelled")
		}
		callCtx, end := context.WithTimeout(ctx, time.Duration(m.cfg.TimeoutSec)*time.Second)
		defer end()
		result, err := m.session.CallTool(callCtx, &mcp.CallToolParams{Name: name, Arguments: json.RawMessage(body)})
		if err != nil {
			if callCtx.Err() != nil {
				m.mu.Lock()
				m.retired = true
				m.mu.Unlock()
				m.close()
			}
			// Upstream errors may contain credentials. Never expose their text.
			return reject("upstream_failed_or_timed_out")
		}
		if result.NeedsInput() {
			return reject("server_input_requests_are_disabled")
		}
		for _, c := range result.Content {
			if _, ok := c.(*mcp.TextContent); !ok {
				return reject("non_text_content_is_disabled")
			}
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return reject("invalid_result")
		}
		if len(encoded) > m.cfg.MaxResponseBytes {
			return reject("response_too_large")
		}
		cleaned, d := resultFilter.Request(encoded, m.filter)
		if d.Action == filter.Block {
			return reject("result:" + d.Rule)
		}
		verdict := g.detector.Scan(callCtx, "mcp_result", cleaned)
		if verdict.Model != "" {
			decision := "allow"
			if verdict.Block {
				decision = "deny"
			}
			if verdict.Flag {
				decision = "flag"
			}
			if err := g.audit.write(event{Type: "injection.scanned", ID: id, Server: m.name, Tool: name, Decision: decision, Rule: verdict.Rule, Model: verdict.Model, Score: verdict.Score, ArgumentsHash: verdict.Hash}); err != nil {
				return nil, fmt.Errorf("MCP audit unavailable")
			}
		}
		if verdict.Block {
			return reject(verdict.Rule)
		}
		if err := json.Unmarshal(cleaned, &result); err != nil {
			return reject("invalid_filtered_result")
		}
		if output != nil && !result.IsError {
			structured, err := json.Marshal(result.StructuredContent)
			if err != nil || schemaValue(output, structured) != nil {
				return reject("result_schema")
			}
		}
		if err := g.audit.write(event{Type: "call.completed", ID: id, Server: m.name, Tool: name, Decision: "allow", DurationMS: time.Since(started).Milliseconds(), Bytes: len(cleaned)}); err != nil {
			return nil, fmt.Errorf("MCP audit unavailable")
		}
		return result, nil
	}
}

type remoteTransport struct {
	base    *http.Transport
	headers http.Header
}

func (t *remoteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range t.headers {
		r.Header[k] = append([]string(nil), v...)
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		resp.Body = &boundedBody{ReadCloser: resp.Body, remaining: 16 << 20}
	}
	return resp, nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, fmt.Errorf("MCP HTTP response exceeds transport limit")
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func callName(req mcp.Request) string {
	if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok {
		return p.Name
	}
	return ""
}
