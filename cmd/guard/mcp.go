package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"

	"guard/internal/mcpguard"
	"guard/internal/policy"
	"guard/internal/proxy"
	"guard/internal/sandbox"
)

// Local MCP processes run under a separate read allowlist, never in trusted guard.
func mcpCommandFactory(parent *policy.Resolved) mcpguard.CommandFactory {
	return func(ctx context.Context, name string, s mcpguard.Server) (*exec.Cmd, func(), error) {
		executable, err := exec.LookPath(s.Command[0])
		if err != nil {
			return nil, nil, err
		}
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			return nil, nil, err
		}
		s.Command = append([]string(nil), s.Command...)
		s.Command[0] = executable
		runtimeDir, err := os.MkdirTemp("", "guard-mcp-*")
		if err != nil {
			return nil, nil, err
		}
		runtimeDir, err = filepath.EvalSymlinks(runtimeDir)
		if err != nil {
			return nil, nil, err
		}
		cleanup := func() { os.RemoveAll(runtimeDir) }
		success := false
		defer func() {
			if !success {
				cleanup()
			}
		}()
		home := filepath.Join(runtimeDir, "home")
		tmp := filepath.Join(runtimeDir, "tmp")
		for _, p := range []string{home, tmp} {
			if err := os.Mkdir(p, 0700); err != nil {
				return nil, nil, err
			}
		}
		r := &policy.Resolved{Workspace: parent.Workspace, Writable: append([]string{runtimeDir}, s.Sandbox.Writable...), ReadAllow: append([]string{runtimeDir, s.Command[0], "/System", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/Library/Developer", "/Library/Apple/System/Library", "/dev", "/private/etc", "/private/var/db/dyld"}, s.Sandbox.ReadAllow...), ReadDeny: append([]string(nil), parent.ReadDeny...), SelfProtect: append([]string(nil), parent.SelfProtect...), EnvAllow: map[string]bool{}, ExecDeny: parent.ExecDeny, ExecAllow: parent.ExecAllow}
		env := []string{"HOME=" + home, "TMPDIR=" + tmp, "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
		extra := []string{}
		for _, name := range s.EnvAllow {
			if value, ok := os.LookupEnv(name); ok {
				extra = append(extra, name+"="+value)
			}
		}
		env = overrideEnv(env, extra)
		var px *proxy.Proxy
		if len(s.Sandbox.AllowDomains) > 0 {
			r.AllowDomains = s.Sandbox.AllowDomains
			px, err = proxy.New(r, log.New(io.Discard, "", 0))
			if err != nil {
				return nil, nil, err
			}
			port, err := px.Start(0)
			if err != nil {
				px.CloseFilter()
				return nil, nil, err
			}
			r.ProxyPort = port
			endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
			env = append(env, "HTTP_PROXY="+endpoint, "HTTPS_PROXY="+endpoint, "http_proxy="+endpoint, "https_proxy="+endpoint)
			previous := cleanup
			cleanup = func() { px.Close(); px.CloseFilter(); previous() }
		}
		profile, err := sandbox.Profile(r)
		if err != nil {
			return nil, nil, err
		}
		path := filepath.Join(runtimeDir, "server.sb")
		if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
			return nil, nil, err
		}
		r.SelfProtect = append(r.SelfProtect, path)
		// Re-render after protecting the profile itself.
		profile, err = sandbox.Profile(r)
		if err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
			return nil, nil, err
		}
		cmd, commandCleanup, err := buildCommand(r, path, env, s.Command)
		if err != nil {
			return nil, nil, err
		}
		previousCleanup := cleanup
		cleanup = func() { commandCleanup(); previousCleanup() }
		cmd.Dir = parent.Workspace
		cmd.Stderr = io.Discard // server stderr may contain credentials
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		previous := cleanup
		cleanup = func() {
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			previous()
		}
		success = true
		return cmd, cleanup, nil
	}
}

func mcpConfigText(c mcpguard.Config, port int, token string) string {
	names := make([]string, 0, len(c.Servers))
	for name := range c.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	text := ""
	for _, name := range names {
		s := c.Servers[name]
		timeout := s.TimeoutSec
		if timeout == 0 {
			timeout = 60
		}
		approval := s.ApprovalTimeoutSec
		if approval == 0 {
			approval = 120
		}
		text += fmt.Sprintf("\n[mcp_servers.%s]\nurl = %s\nrequired = true\nstartup_timeout_sec = 20\ntool_timeout_sec = %d\nhttp_headers = { Authorization = %s }\n", name, strconv.Quote(fmt.Sprintf("http://127.0.0.1:%d%s%s", port, mcpguard.Prefix, name)), timeout+approval+5, strconv.Quote("Bearer "+token))
	}
	return text
}
func mcpCmd(args []string) {
	if len(args) > 0 && args[0] == "bridge" {
		fs := flag.NewFlagSet("mcp bridge", flag.ContinueOnError)
		name := fs.String("server", "", "managed server name")
		if err := fs.Parse(args[1:]); err != nil {
			die("%v", err)
		}
		if *name == "" || fs.NArg() != 0 {
			die("usage: guard mcp bridge --server NAME")
		}
		if err := runMCPBridge(context.Background(), os.Getenv("GUARD_MCP_CONFIG"), *name); err != nil {
			die("MCP bridge: %v", err)
		}
		return
	}

	if len(args) == 0 {
		die("usage: guard mcp pending|approve|deny --policy FILE [--id ID]")
	}
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	path := fs.String("policy", "", "guard policy")
	id := fs.String("id", "", "approval ID")
	if err := fs.Parse(args[1:]); err != nil {
		die("%v", err)
	}
	if *path == "" || fs.NArg() != 0 {
		die("--policy is required")
	}
	r, err := policy.Load(*path)
	if err != nil {
		die("%v", err)
	}
	if len(r.MCP.Servers) == 0 {
		die("no managed MCP servers configured")
	}
	switch args[0] {
	case "pending":
		pending, err := mcpguard.Pending(r.MCP.ApprovalDir)
		if err != nil {
			die("%v", err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(pending); err != nil {
			die("%v", err)
		}
	case "approve", "deny":
		if err := mcpguard.Decide(r.MCP.ApprovalDir, *id, args[0] == "approve"); err != nil {
			die("%v", err)
		}
		fmt.Printf("MCP request %s: %s\n", *id, args[0])
	default:
		die("unknown MCP command %q", args[0])
	}
}

// MCPConnections is a per-launch client configuration, containing gateway-only
// credentials. Backend credentials remain exclusively in the trusted parent.
type MCPConnections struct {
	Servers map[string]MCPConnection `json:"mcpServers"`
}
type MCPConnection struct {
	Type    string            `json:"type"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

func writeMCPConnections(path string, cfg mcpguard.Config, port int, token string) error {
	c := MCPConnections{Servers: map[string]MCPConnection{}}
	for name := range cfg.Servers {
		c.Servers[name] = MCPConnection{Type: "http", URL: fmt.Sprintf("http://127.0.0.1:%d%s%s", port, mcpguard.Prefix, name), Headers: map[string]string{"Authorization": "Bearer " + token}}
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

type mcpHeaderTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t mcpHeaderTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range t.headers {
		r.Header.Set(k, v)
	}
	return t.base.RoundTrip(r)
}
func runMCPBridge(ctx context.Context, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open GUARD_MCP_CONFIG: %w", err)
	}
	defer f.Close()
	var cfg MCPConnections
	if err := json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&cfg); err != nil {
		return err
	}
	connection, ok := cfg.Servers[name]
	if !ok {
		return fmt.Errorf("unknown managed MCP server %q", name)
	}
	u, err := url.Parse(connection.URL)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != mcpguard.Prefix+name || u.RawQuery != "" || u.User != nil || u.Fragment != "" || !strings.HasPrefix(connection.Headers["Authorization"], "Bearer ") {
		return fmt.Errorf("invalid guard gateway connection")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: mcpHeaderTransport{transport, connection.Headers}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	upstream, err := mcp.NewClient(&mcp.Implementation{Name: "guard-stdio-bridge", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: connection.URL, HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return err
	}
	defer upstream.Close()
	catalog, err := upstream.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		return err
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "guard-" + name, Version: "1"}, nil)
	for _, tool := range catalog.Tools {
		toolName := tool.Name
		server.AddTool(tool, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return upstream.CallTool(ctx, &mcp.CallToolParams{Name: toolName, Arguments: r.Params.Arguments})
		})
	}
	return server.Run(ctx, &mcp.StdioTransport{})
}
