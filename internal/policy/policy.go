// Package policy loads and normalizes a guard policy.
//
// The policy is the single source of truth: everything the sandbox and the
// egress proxy enforce is derived from it. It is intentionally declarative so a
// human can review exactly what an agent is allowed to touch.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"guard/internal/credential"
	"guard/internal/filter"
	"guard/internal/guardrails"
	"guard/internal/mcpguard"
)

// KeyInjection describes a reverse-proxy route that adds an auth header the
// sandboxed harness never sees. The harness points its API base URL at
// http://127.0.0.1:<port><Prefix>; guard forwards to Upstream and attaches
// Header with the value taken from guard's own environment (Env).
type KeyInjection struct {
	Auth         credential.Config `json:"auth"`
	Prefix       string            `json:"prefix"`        // e.g. "/anthropic"
	Upstream     string            `json:"upstream"`      // e.g. "https://api.anthropic.com"
	Header       string            `json:"header"`        // e.g. "x-api-key"
	Env          string            `json:"env"`           // name of env var in guard holding the secret
	HeaderPrefix string            `json:"header_prefix"` // e.g. "Bearer "
	JSON         filter.JSONPolicy `json:"json"`
	// Request allowlist (default-deny when non-empty). The agent may only issue
	// requests whose method is in Methods AND whose upstream path (after the
	// prefix is stripped) equals an AllowPaths entry. A trailing / permits a
	// subtree. Empty list = allow any.
	Methods    []string `json:"methods"`
	AllowPaths []string `json:"allow_paths"`
	// Structured query-parameter policy (e.g. for a search endpoint): control
	// exactly which params may appear and filter a named param's value.
	Query QueryPolicy `json:"query"`
}

// QueryPolicy inspects a request's URL query by parameter, rather than by
// regex over the whole string. AllowParams, when non-empty, rejects any param
// not listed; DenyParams always reject; MaxParamLen caps a value's length; and
// ParamRules apply a block/flag/redact action to one named param's value.
type QueryPolicy struct {
	AllowParams []string    `json:"allow_params"`
	DenyParams  []string    `json:"deny_params"`
	MaxParamLen int         `json:"max_param_len"`
	ParamRules  []ParamRule `json:"param_rules"`
}

// ParamRule is a content rule scoped to a single query parameter.
type ParamRule struct {
	Param   string `json:"param"`
	Pattern string `json:"pattern"`
	Action  string `json:"action"` // "block" | "flag" | "redact"
}

// Enabled reports whether any query rule is configured.
func (q QueryPolicy) Enabled() bool {
	return len(q.AllowParams) > 0 || len(q.DenyParams) > 0 || q.MaxParamLen > 0 || len(q.ParamRules) > 0
}

// Policy is the raw, as-written form.
type Codex struct {
	Model  string `json:"model"`
	Route  string `json:"route"`
	Binary string `json:"binary"`
}

type Policy struct {
	Guardrails   guardrails.Config `json:"guardrails"`
	MCP          mcpguard.Config   `json:"mcp"`
	Codex        Codex             `json:"codex"`
	Workspace    string            `json:"workspace"`     // the one directory the agent may write in
	Writable     []string          `json:"writable"`      // extra writable paths
	ReadDeny     []string          `json:"read_deny"`     // paths the agent may not read (secrets)
	SelfProtect  []string          `json:"self_protect"`  // paths inside writable the agent may NOT write (persistence)
	AllowDomains []string          `json:"allow_domains"` // domains reachable through the proxy
	EnvAllow     []string          `json:"env_allow"`     // env var names passed through verbatim
	ProxyPort    int               `json:"proxy_port"`    // 0 = auto-assign
	KeyInject    []KeyInjection    `json:"key_injection"`
	PromptFilter filter.Config     `json:"prompt_filter"` // content firewall on LLM traffic
	Exec         ExecPolicy        `json:"exec"`          // which executables the agent may run
	Limits       Limits            `json:"limits"`        // rate / budget caps on egress
}

// Limits caps how much the agent can send out this session, so even permitted
// requests can't be used to spam, run up a bill, or exfiltrate in small pieces.
// A zero field means "no limit" for that dimension.
type Limits struct {
	MaxRequests     int   `json:"max_requests"`      // total egress requests this session
	RatePerMin      int   `json:"rate_per_min"`      // requests allowed per 60s window
	MaxRequestBytes int64 `json:"max_request_bytes"` // cumulative outbound body bytes
}

// ExecPolicy filters the local "tools" the agent can run. Deny is a denylist of
// executables that are always refused (robust default). Allow, when non-empty,
// switches to allowlist mode: everything not listed is denied — stronger, but
// needs tuning because shells/interpreters re-exec helper binaries.
type ExecPolicy struct {
	Deny  []string `json:"deny"`
	Allow []string `json:"allow"`
}

// Resolved is Policy with ~ and relative paths expanded to absolute paths, and
// with self-protected paths resolved relative to the workspace.
type Resolved struct {
	TerminalDevice string // per-launch PTY, chosen by the trusted parent
	Guardrails     guardrails.Config
	MCP            mcpguard.Config
	ReadAllow      []string // optional read allowlist used for managed MCP processes
	Raw            Policy
	Workspace      string
	Writable       []string // absolute, includes Workspace
	ReadDeny       []string // absolute
	SelfProtect    []string // absolute, under Workspace
	AllowDomains   []string
	EnvAllow       map[string]bool
	ProxyPort      int
	KeyInject      []KeyInjection
	PromptFilter   filter.Config
	ExecDeny       []string // absolute executable paths
	ExecAllow      []string // absolute executable paths (allowlist mode when non-empty)
	Limits         Limits
}

func expand(home, base, p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path in policy")
	}
	if strings.HasPrefix(p, "~/") {
		p = filepath.Join(home, p[2:])
	} else if p == "~" {
		p = home
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	return canonical(p)
}

// Load reads, parses and resolves a policy file.
func Load(path string) (*Resolved, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	if err := ensureEOF(dec); err != nil {
		return nil, err
	}

	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	ws, err := expand(home, cwd, p.Workspace)
	if err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	if fi, err := os.Stat(ws); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("workspace %q is not an existing directory", ws)
	}

	r := &Resolved{
		Raw:          p,
		Guardrails:   p.Guardrails,
		MCP:          p.MCP,
		Workspace:    ws,
		AllowDomains: p.AllowDomains,
		EnvAllow:     map[string]bool{},
		ProxyPort:    p.ProxyPort,
		KeyInject:    p.KeyInject,
		PromptFilter: p.PromptFilter,
		Limits:       p.Limits,
	}
	// The audit log is written by guard (outside the sandbox); resolve it so a
	// relative path lands predictably and cannot be tampered with from inside.
	if p.PromptFilter.AuditLog != "" {
		abs, err := expand(home, cwd, p.PromptFilter.AuditLog)
		if err != nil {
			return nil, fmt.Errorf("prompt_filter.audit_log: %w", err)
		}
		r.PromptFilter.AuditLog = abs
	}
	if p.Guardrails.AuditLog != "" {
		abs, err := expand(home, cwd, p.Guardrails.AuditLog)
		if err != nil {
			return nil, err
		}
		r.Guardrails.AuditLog = abs
	}
	r.Writable = append(r.Writable, ws)
	for _, w := range p.Writable {
		abs, err := expand(home, cwd, w)
		if err != nil {
			return nil, fmt.Errorf("writable: %w", err)
		}
		r.Writable = append(r.Writable, abs)
	}
	for _, d := range p.ReadDeny {
		abs, err := expand(home, cwd, d)
		if err != nil {
			return nil, fmt.Errorf("read_deny: %w", err)
		}
		r.ReadDeny = append(r.ReadDeny, abs)
	}
	for _, s := range p.SelfProtect {
		// self-protected paths are relative to the workspace unless absolute/~.
		abs, err := expand(home, ws, s)
		if err != nil {
			return nil, fmt.Errorf("self_protect: %w", err)
		}
		r.SelfProtect = append(r.SelfProtect, abs)
	}
	for _, e := range p.EnvAllow {
		r.EnvAllow[e] = true
	}
	for _, e := range p.Exec.Deny {
		abs, err := expand(home, cwd, e)
		if err != nil {
			return nil, fmt.Errorf("exec.deny: %w", err)
		}
		r.ExecDeny = append(r.ExecDeny, abs)
	}
	for _, e := range p.Exec.Allow {
		abs, err := expand(home, cwd, e)
		if err != nil {
			return nil, fmt.Errorf("exec.allow: %w", err)
		}
		r.ExecAllow = append(r.ExecAllow, abs)
	}
	policyFile, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	policyFile, err = canonical(policyFile)
	if err != nil {
		return nil, err
	}
	r.SelfProtect = append(r.SelfProtect, policyFile)
	if err := r.validate(); err != nil {
		return nil, err
	}
	if err := r.resolveMCP(); err != nil {
		return nil, err
	}
	if r.Guardrails.Strict {
		for name, server := range r.MCP.Servers {
			if len(server.Sandbox.AllowDomains) > 0 {
				return nil, fmt.Errorf("strict guardrails prohibit raw egress from local MCP server %s", name)
			}
		}
	}
	if len(r.MCP.Servers) > 0 && r.Guardrails.AuditLog != "" && r.MCP.AuditLog == r.Guardrails.AuditLog {
		return nil, fmt.Errorf("MCP and guardrail audit logs must differ")
	}
	return r, nil
}
