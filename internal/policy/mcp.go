package policy

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"guard/internal/mcpguard"
)

func (r *Resolved) resolveMCP() error {
	if err := mcpguard.Validate(r.MCP); err != nil {
		return err
	}
	if len(r.MCP.Servers) == 0 {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if r.MCP.AuditLog == "" {
		if r.PromptFilter.AuditLog == "" {
			return fmt.Errorf("MCP requires mcp.audit_log or prompt_filter.audit_log")
		}
		r.MCP.AuditLog = r.PromptFilter.AuditLog + ".mcp.jsonl"
	}
	r.MCP.AuditLog, err = expand(home, cwd, r.MCP.AuditLog)
	if err != nil {
		return err
	}
	if r.MCP.ApprovalDir == "" {
		r.MCP.ApprovalDir = r.MCP.AuditLog + ".approvals"
	}
	r.MCP.ApprovalDir, err = expand(home, cwd, r.MCP.ApprovalDir)
	if err != nil {
		return err
	}
	for _, protected := range []string{r.MCP.AuditLog, r.MCP.ApprovalDir} {
		for _, w := range r.Writable {
			if contains(w, protected) {
				return fmt.Errorf("MCP audit and approvals must be outside writable paths")
			}
		}
		r.ReadDeny = append(r.ReadDeny, protected)
		r.SelfProtect = append(r.SelfProtect, protected)
	}
	if contains(r.MCP.ApprovalDir, r.MCP.AuditLog) {
		return fmt.Errorf("MCP audit log must be outside its approval directory")
	}
	if r.MCP.AuditLog == r.PromptFilter.AuditLog {
		return fmt.Errorf("MCP audit log must differ from prompt audit log")
	}
	for name, s := range r.MCP.Servers {
		if s.URL != "" {
			endpoint, _ := url.Parse(s.URL)
			for _, domain := range r.AllowDomains {
				if strings.EqualFold(domain, endpoint.Hostname()) {
					return fmt.Errorf("managed MCP host must not also be allowed for raw egress")
				}
			}
		}
		if len(s.Command) > 0 {
			command := s.Command[0]
			if filepath.IsAbs(command) || len(command) > 0 && command[0] == '~' {
				command, err = expand(home, cwd, command)
			} else {
				command, err = exec.LookPath(command)
				if err == nil {
					command, err = filepath.Abs(command)
				}
			}
			if err != nil {
				return fmt.Errorf("MCP %s executable unavailable", name)
			}
			command, err = canonical(command)
			if err != nil {
				return err
			}
			s.Command[0] = command
			r.SelfProtect = append(r.SelfProtect, command)
			for _, paths := range [][]string{s.Sandbox.ReadAllow, s.Sandbox.Writable} {
				for i, p := range paths {
					paths[i], err = expand(home, cwd, p)
					if err != nil {
						return err
					}
				}
			}
			for _, w := range s.Sandbox.Writable {
				allowed := false
				for _, parent := range r.Writable {
					if contains(parent, w) {
						allowed = true
					}
				}
				if !allowed {
					return fmt.Errorf("MCP %s writable path must be inside guard writable paths", name)
				}
			}
			for _, variable := range s.EnvAllow {
				for _, ki := range r.KeyInject {
					if variable == ki.Env && variable != "" {
						return fmt.Errorf("MCP %s must not inherit model credentials", name)
					}
				}
			}
		}
		if s.BearerEnv != "" && r.EnvAllow[s.BearerEnv] {
			return fmt.Errorf("MCP bearer credentials must not enter agent env_allow")
		}
		r.MCP.Servers[name] = s
	}
	return nil
}
