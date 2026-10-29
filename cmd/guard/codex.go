package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"guard/internal/credential"
	"guard/internal/filter"
	"guard/internal/mcpguard"
	"guard/internal/policy"
)

func initCmd(args []string) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	ws := fs.String("workspace", "", "directory Codex may modify")
	output := fs.String("output", "guard.json", "new policy file (never overwritten)")
	model := fs.String("model", "", "model ID available to your account")
	exampleMCP := fs.String("mcp-example", "", "native example MCP executable (echo requires approval)")
	authMode := fs.String("auth", "chatgpt", "chatgpt (existing Codex login) or api")
	if err := fs.Parse(args); err != nil {
		die("%v", err)
	}
	if *ws == "" || fs.NArg() != 0 {
		die("usage: guard init --workspace DIR [--output guard.json] [--auth chatgpt|api] [--model MODEL]")
	}
	if *authMode != "chatgpt" && *authMode != "api" {
		die("--auth must be chatgpt or api")
	}
	abs, err := filepath.Abs(*ws)
	if err != nil {
		die("%v", err)
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		die("%v", err)
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		die("%v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		die("%v", err)
	}
	logs := filepath.Join(home, ".guard", "logs")
	if err := os.MkdirAll(logs, 0700); err != nil {
		die("%v", err)
	}
	p := policy.Policy{
		Workspace:   abs,
		ReadDeny:    []string{"~/.ssh", "~/.aws", "~/.config/gh", "~/.codex", "~/.claude", "~/.hermes", "~/.guard", "~/Library/Keychains"},
		SelfProtect: []string{".git/hooks", ".git/config", ".envrc", ".codex", ".claude"},
		EnvAllow:    []string{"PATH", "USER", "LOGNAME", "TERM", "COLORTERM", "LANG", "LC_ALL"},
		Codex:       policy.Codex{Model: *model, Route: "/openai", Binary: "codex"},
		KeyInject:   []policy.KeyInjection{{Prefix: "/openai", Upstream: "https://api.openai.com", Header: "Authorization", HeaderPrefix: "Bearer ", Env: "OPENAI_API_KEY", Methods: []string{"POST"}, AllowPaths: []string{"/v1/responses", "/v1/responses/compact"}, JSON: filter.JSONPolicy{RequireJSON: true}}},
		PromptFilter: filter.Config{Enabled: true, Mode: "enforce", MaxBodyBytes: 4 << 20, AuditLog: filepath.Join(logs, fmt.Sprintf("session-%d.log", time.Now().UnixNano())), Redact: []filter.Rule{
			{Name: "email", Pattern: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, Action: "redact"},
			{Name: "phone", Pattern: `\+[0-9][0-9 ()-]{8,}[0-9]`, Action: "redact"},
		}},
		Limits: policy.Limits{MaxRequests: 500, RatePerMin: 60, MaxRequestBytes: 50 << 20},
	}
	if *authMode == "chatgpt" {
		p.Codex.Route = "/codex"
		p.KeyInject = []policy.KeyInjection{{Prefix: "/codex", Upstream: "https://chatgpt.com", Auth: credential.Config{Type: "codex"}, Methods: []string{"POST"}, AllowPaths: []string{"/backend-api/codex/responses", "/backend-api/codex/responses/compact"}, JSON: filter.JSONPolicy{RequireJSON: true}}}
	}
	if *model != "" {
		p.KeyInject[0].JSON.AllowModels = []string{*model}
	}
	p.MCP.Servers = map[string]mcpguard.Server{}
	if *exampleMCP != "" {
		executable, err := filepath.Abs(*exampleMCP)
		if err != nil {
			die("%v", err)
		}
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			die("MCP example executable: %v", err)
		}
		p.MCP.Servers["example"] = mcpguard.Server{Command: []string{executable}, Tools: map[string]mcpguard.Tool{"echo": {Action: "ask"}}}
	}
	body, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		die("%v", err)
	}
	fh, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		die("create policy: %v", err)
	}
	_, err = fh.Write(append(body, '\n'))
	closeErr := fh.Close()
	if err != nil {
		die("%v", err)
	}
	if closeErr != nil {
		die("%v", closeErr)
	}
	fmt.Printf("Created %s\nWorkspace: %s\nAudit log: %s\nRun: guard codex --policy %s\n", *output, abs, p.PromptFilter.AuditLog, *output)
}

func codexCmd(args []string) {
	path, dry, argv := parseArgs(args)
	if path == "" {
		die("--policy is required")
	}
	r, err := policy.Load(path)
	if err != nil {
		die("%v", err)
	}
	finishLaunch(runLaunch(r, dry, argv, os.Stdin, true))
}

func prepareCodex(r *policy.Resolved, port int, args []string, gatewayToken string) (argv, env []string, cleanup func(), err error) {
	cfg := r.Raw.Codex
	if cfg.Route == "" {
		cfg.Route = "/openai"
	}
	found := false
	apiPath := "/v1"
	for _, rt := range r.KeyInject {
		if rt.Prefix == cfg.Route {
			found = true
			if rt.Auth.Type == "codex" {
				apiPath = "/backend-api/codex"
			}
		}
	}
	if !found {
		return nil, nil, nil, fmt.Errorf("codex.route %q does not match key_injection", cfg.Route)
	}
	if cfg.Binary == "" {
		cfg.Binary = "codex"
	}
	binary, err := exec.LookPath(cfg.Binary)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Codex CLI not found: %w", err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return nil, nil, nil, err
	}
	session, err := os.MkdirTemp("", "guard-codex-*")
	if err != nil {
		return nil, nil, nil, err
	}
	session, err = filepath.EvalSymlinks(session)
	if err != nil {
		return nil, nil, nil, err
	}
	cleanup = func() { os.RemoveAll(session) }
	success := false
	defer func() {
		if !success {
			cleanup()
		}
	}()
	codexHome := filepath.Join(session, "codex")
	home := filepath.Join(session, "home")
	bin := filepath.Join(session, "bin")
	tmp := filepath.Join(session, "tmp")
	for _, d := range []string{codexHome, home, bin, tmp} {
		if err = os.MkdirAll(d, 0700); err != nil {
			return
		}
	}
	// A native Codex install may live under the real ~/.codex, which is denied.
	// Stage only the executable, never the user's auth, config, hooks or plugins.
	staged := filepath.Join(bin, "codex")
	src, e := os.Open(binary)
	if e != nil {
		err = e
		return
	}
	defer src.Close()
	magic := make([]byte, 2)
	if _, e = io.ReadFull(src, magic); e != nil {
		err = e
		return
	}
	if string(magic) == "#!" {
		err = fmt.Errorf("guard codex requires a native Codex executable; set codex.binary to its path")
		return
	}
	if _, e = src.Seek(0, io.SeekStart); e != nil {
		err = e
		return
	}
	dst, e := os.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if e != nil {
		err = e
		return
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		err = copyErr
		return
	}
	if closeErr != nil {
		err = closeErr
		return
	}
	base := fmt.Sprintf("http://127.0.0.1:%d%s%s", port, cfg.Route, apiPath)
	text := fmt.Sprintf(`model_provider = "guard"
sandbox_mode = "danger-full-access"
web_search = "disabled"
check_for_update_on_startup = false
cli_auth_credentials_store = "file"
[model_providers.guard]
name = "Guard filtered proxy"
base_url = %s
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0
`, strconv.Quote(base))
	if cfg.Model != "" {
		text = "model = " + strconv.Quote(cfg.Model) + "\n" + text
	}
	text += mcpConfigText(r.MCP, port, gatewayToken)
	configPath := filepath.Join(codexHome, "config.toml")
	if err = os.WriteFile(configPath, []byte(text), 0600); err != nil {
		return
	}
	r.Writable = append(r.Writable, session)
	r.SelfProtect = append(r.SelfProtect, bin, configPath)
	if realHome, e := os.UserHomeDir(); e == nil {
		r.ReadDeny = append(r.ReadDeny, filepath.Join(realHome, ".codex"))
	}
	if original := os.Getenv("CODEX_HOME"); original != "" {
		r.ReadDeny = append(r.ReadDeny, original)
	}
	env = []string{"HOME=" + home, "CODEX_HOME=" + codexHome, "TMPDIR=" + tmp, "PATH=" + bin + ":" + os.Getenv("PATH")}
	argv = append([]string{staged, "--no-daemon"}, args...)
	success = true
	return
}

func overrideEnv(base, extra []string) []string {
	keys := map[string]bool{}
	for _, kv := range extra {
		k, _, _ := strings.Cut(kv, "=")
		keys[k] = true
	}
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if !keys[k] {
			out = append(out, kv)
		}
	}
	return append(out, extra...)
}
