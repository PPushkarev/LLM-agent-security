// Package mcpguard exposes an allowlisted MCP facade, never a transparent tunnel.
package mcpguard

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"guard/internal/filter"
	"guard/internal/injection"
)

const Prefix = "/__guard/mcp/"
const maxBytes = 8 << 20

type Config struct {
	Injection   injection.Config  `json:"-"`
	AuditLog    string            `json:"audit_log"`
	ApprovalDir string            `json:"approval_dir"`
	Servers     map[string]Server `json:"servers"`
}
type Server struct {
	Command   []string `json:"command"`
	URL       string   `json:"url"`
	EnvAllow  []string `json:"env_allow"`
	BearerEnv string   `json:"bearer_env"`
	// HTTP is accepted only for an explicitly configured loopback test/dev endpoint.
	AllowHTTP          bool            `json:"allow_http"`
	Sandbox            Sandbox         `json:"sandbox"`
	Tools              map[string]Tool `json:"tools"`
	MaxCalls           int             `json:"max_calls"`
	RatePerMin         int             `json:"rate_per_min"`
	MaxParallel        int             `json:"max_parallel"`
	TimeoutSec         int             `json:"timeout_sec"`
	ApprovalTimeoutSec int             `json:"approval_timeout_sec"`
	MaxRequestBytes    int             `json:"max_request_bytes"`
	MaxResponseBytes   int             `json:"max_response_bytes"`
}
type Sandbox struct {
	ReadAllow    []string `json:"read_allow"`
	Writable     []string `json:"writable"`
	AllowDomains []string `json:"allow_domains"`
}
type Tool struct {
	Action    string            `json:"action"` // allow | ask | deny (empty = deny)
	Schema    json.RawMessage   `json:"schema"` // optional extra JSON Schema, ANDed with upstream schema
	Arguments filter.JSONPolicy `json:"arguments"`
	Result    filter.JSONPolicy `json:"result"`
}

var toolNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var nameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func Validate(c Config) error {
	for name, s := range c.Servers {
		if !nameRE.MatchString(name) {
			return fmt.Errorf("invalid MCP server name %q", name)
		}
		if (len(s.Command) > 0) == (s.URL != "") {
			return fmt.Errorf("MCP %s needs exactly one command or URL", name)
		}
		if len(s.Command) > 0 && s.Command[0] == "" {
			return fmt.Errorf("MCP %s has an empty executable", name)
		}
		if s.URL != "" {
			u, err := url.Parse(s.URL)
			if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
				return fmt.Errorf("MCP %s: invalid endpoint", name)
			}
			ip := net.ParseIP(u.Hostname())
			loop := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
			if u.Scheme != "https" && !(s.AllowHTTP && u.Scheme == "http" && loop) {
				return fmt.Errorf("MCP %s requires HTTPS (HTTP only with allow_http on loopback)", name)
			}
			if len(s.EnvAllow) > 0 || len(s.Sandbox.Writable) > 0 || len(s.Sandbox.ReadAllow) > 0 || len(s.Sandbox.AllowDomains) > 0 {
				return fmt.Errorf("MCP %s: local sandbox options cannot be used for remote servers", name)
			}
		} else if s.BearerEnv != "" {
			return fmt.Errorf("MCP %s: bearer_env is for remote servers", name)
		}
		if len(s.Tools) == 0 {
			return fmt.Errorf("MCP %s needs an explicit tool policy", name)
		}
		for tool, t := range s.Tools {
			if !toolNameRE.MatchString(tool) {
				return fmt.Errorf("MCP %s: invalid tool name", name)
			}
			switch t.Action {
			case "", "deny", "allow", "ask":
			default:
				return fmt.Errorf("MCP %s/%s: invalid action", name, tool)
			}
			if _, err := compileSchema(t.Schema); err != nil {
				return fmt.Errorf("MCP %s/%s schema: %w", name, tool, err)
			}
			if _, err := filter.NewJSON(t.Arguments); err != nil {
				return err
			}
			if _, err := filter.NewJSON(t.Result); err != nil {
				return err
			}
		}
		for _, v := range []int{s.MaxCalls, s.RatePerMin, s.MaxParallel, s.TimeoutSec, s.ApprovalTimeoutSec, s.MaxRequestBytes, s.MaxResponseBytes} {
			if v < 0 {
				return fmt.Errorf("MCP %s: limits must not be negative", name)
			}
		}
		if s.MaxRequestBytes > maxBytes || s.MaxResponseBytes > maxBytes || s.MaxParallel > 32 || s.TimeoutSec > 600 || s.ApprovalTimeoutSec > 600 {
			return fmt.Errorf("MCP %s: limits exceed safety ceilings (8 MiB, 32 parallel, 600 seconds)", name)
		}
	}
	return nil
}
func defaults(s Server) Server {
	if s.MaxParallel == 0 {
		s.MaxParallel = 1
	}
	if s.TimeoutSec == 0 {
		s.TimeoutSec = 60
	}
	if s.ApprovalTimeoutSec == 0 {
		s.ApprovalTimeoutSec = 120
	}
	if s.MaxRequestBytes == 0 {
		s.MaxRequestBytes = 1 << 20
	}
	if s.MaxResponseBytes == 0 {
		s.MaxResponseBytes = 2 << 20
	}
	if s.MaxCalls == 0 {
		s.MaxCalls = 500
	}
	if s.RatePerMin == 0 {
		s.RatePerMin = 60
	}
	return s
}
func compileSchema(raw json.RawMessage) (*jsonschema.Resolved, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	// Never fetch remote $refs supplied by a server or policy.
	return schema.Resolve(&jsonschema.ResolveOptions{Loader: func(*url.URL) (*jsonschema.Schema, error) {
		return nil, fmt.Errorf("external schema references are disabled")
	}})
}
func schemaValue(schema *jsonschema.Resolved, body []byte) error {
	if schema == nil {
		return nil
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	return schema.Validate(v)
}
func isObject(body []byte) bool { return strings.HasPrefix(strings.TrimSpace(string(body)), "{") }
