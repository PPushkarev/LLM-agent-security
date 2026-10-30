package policy

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"guard/internal/filter"
	"guard/internal/injection"
)

// canonical also resolves symlinks in existing parents of a not-yet-created path.
func canonical(path string) (string, error) {
	path = filepath.Clean(path)
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(path)
		if err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", err
		}
		tail = append(tail, filepath.Base(path))
		path = parent
	}
}
func contains(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func (r *Resolved) validate() error {
	if err := injection.Validate(r.PromptInjection); err != nil {
		return err
	}
	if r.Guardrails.RequirePromptInjection {
		cfg := r.PromptInjection.Defaults()
		if !cfg.Enabled || cfg.Action != "block" {
			return fmt.Errorf("guardrails require blocking prompt injection detection")
		}
		for _, required := range []string{"prompt", "model_request", "mcp_result"} {
			found := false
			for _, source := range cfg.Sources {
				if source == required {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("required prompt injection source missing: %s", required)
			}
		}
	}
	g := r.Guardrails
	if g.MaxSessionSeconds < 0 || g.MaxSessionSeconds > 604800 || g.MaxOutputBytes < 0 {
		return fmt.Errorf("invalid guardrail limits (session maximum is 7 days)")
	}
	if g.Strict {
		if !r.PromptFilter.Enabled || r.PromptFilter.Mode == "monitor" {
			return fmt.Errorf("strict guardrails require content filtering in enforce mode")
		}
		if !r.PromptFilter.ScanResponses {
			return fmt.Errorf("strict guardrails require model response scanning")
		}
		if len(r.AllowDomains) > 0 {
			return fmt.Errorf("strict guardrails prohibit raw egress; use inspected key_injection routes")
		}
		if g.AuditLog == "" || r.PromptFilter.AuditLog == "" {
			return fmt.Errorf("strict guardrails require session and content audit logs")
		}
		if g.MaxSessionSeconds == 0 || g.MaxOutputBytes == 0 {
			return fmt.Errorf("strict guardrails require positive session and output limits")
		}
		if r.Limits.MaxRequests == 0 || r.Limits.MaxRequestBytes == 0 {
			return fmt.Errorf("strict guardrails require request and byte budgets")
		}
		for _, route := range r.KeyInject {
			if !route.JSON.RequireJSON || len(route.Methods) == 0 || len(route.AllowPaths) == 0 {
				return fmt.Errorf("strict guardrails require JSON, method and path restrictions on every route")
			}
		}
	}
	if g.AuditLog != "" {
		audit, err := canonical(g.AuditLog)
		if err != nil {
			return err
		}
		for _, w := range r.Writable {
			if contains(w, audit) {
				return fmt.Errorf("guardrail audit must be outside writable paths")
			}
		}
		if audit == r.PromptFilter.AuditLog {
			return fmt.Errorf("guardrail and content audits must use separate files")
		}
		r.Guardrails.AuditLog = audit
		r.ReadDeny = append(r.ReadDeny, audit)
		r.SelfProtect = append(r.SelfProtect, audit)
	}

	if r.ProxyPort < 0 || r.ProxyPort > 65535 {
		return fmt.Errorf("proxy_port must be between 0 and 65535")
	}
	if r.Limits.MaxRequests < 0 || r.Limits.RatePerMin < 0 || r.Limits.MaxRequestBytes < 0 {
		return fmt.Errorf("limits must not be negative")
	}
	cfg := r.PromptFilter
	cfg.AuditLog = ""
	f, err := filter.New(cfg)
	if err != nil {
		return err
	}
	f.Close()
	seen := map[string]bool{}
	for index := range r.KeyInject {
		ki := &r.KeyInject[index]
		if strings.HasPrefix(ki.Prefix, "/__guard") {
			return fmt.Errorf("/__guard is reserved for internal endpoints")
		}
		if ki.Prefix == "" || !strings.HasPrefix(ki.Prefix, "/") || strings.HasSuffix(ki.Prefix, "/") {
			return fmt.Errorf("invalid route prefix %q", ki.Prefix)
		}
		if seen[ki.Prefix] {
			return fmt.Errorf("duplicate route prefix %q", ki.Prefix)
		}
		seen[ki.Prefix] = true
		for p := range seen {
			if p != ki.Prefix && (strings.HasPrefix(p, ki.Prefix+"/") || strings.HasPrefix(ki.Prefix, p+"/")) {
				return fmt.Errorf("overlapping route prefixes %q and %q", p, ki.Prefix)
			}
		}
		u, err := url.Parse(ki.Upstream)
		if err != nil {
			return fmt.Errorf("invalid upstream URL")
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return fmt.Errorf("upstream must be an http(s) origin")
		}
		if ki.Auth.Type != "" {
			if ki.Auth.Type != "codex" {
				return fmt.Errorf("unsupported route auth type %q", ki.Auth.Type)
			}
			if ki.Env != "" || ki.Header != "" {
				return fmt.Errorf("route must use either codex auth or env key injection")
			}
			if u.Scheme != "https" || u.Host != "chatgpt.com" {
				return fmt.Errorf("Codex subscription credentials may only be sent to https://chatgpt.com")
			}
			home := ki.Auth.CodexHome
			if home == "" {
				home = os.Getenv("CODEX_HOME")
			}
			if home == "" {
				h, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				home = filepath.Join(h, ".codex")
			}
			absolute, err := filepath.Abs(home)
			if err != nil {
				return err
			}
			absolute, err = canonical(absolute)
			if err != nil {
				return err
			}
			ki.Auth.CodexHome = absolute
			for _, w := range r.Writable {
				if contains(w, absolute) {
					return fmt.Errorf("Codex auth directory must be outside writable paths")
				}
			}
			authFile, err := canonical(filepath.Join(absolute, "auth.json"))
			if err != nil {
				return err
			}
			for _, w := range r.Writable {
				if contains(w, authFile) {
					return fmt.Errorf("Codex auth cache must be outside writable paths")
				}
			}
			r.ReadDeny = append(r.ReadDeny, absolute, authFile)
		}
		if ki.Env != "" && (ki.Header == "" || r.EnvAllow[ki.Env]) {
			return fmt.Errorf("credential %s needs a header and must not appear in env_allow", ki.Env)
		}
		if ki.Query.MaxParamLen < 0 {
			return fmt.Errorf("max_param_len must not be negative")
		}
		for _, pr := range ki.Query.ParamRules {
			if _, err := regexp.Compile(pr.Pattern); err != nil {
				return err
			}
			switch pr.Action {
			case "", "block", "redact", "flag":
			default:
				return fmt.Errorf("invalid query rule action %q", pr.Action)
			}
		}
		if _, err := filter.NewJSON(ki.JSON); err != nil {
			return err
		}
	}
	if r.PromptFilter.AuditLog != "" {
		audit, err := canonical(r.PromptFilter.AuditLog)
		if err != nil {
			return err
		}
		r.PromptFilter.AuditLog = audit
		for _, w := range r.Writable {
			if contains(w, audit) {
				return fmt.Errorf("audit log must be outside writable paths: %s", w)
			}
		}
		r.ReadDeny = append(r.ReadDeny, audit)
		r.SelfProtect = append(r.SelfProtect, audit)
	}
	return nil
}

// EnsureEOF rejects a second document or trailing garbage after a policy.
func ensureEOF(dec interface{ Decode(any) error }) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("policy must contain exactly one JSON document")
	}
	return nil
}
