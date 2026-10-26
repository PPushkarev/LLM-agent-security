//go:build darwin

// Package sandbox turns a resolved policy into an OS-level confinement for the
// harness process and all its children.
//
// On macOS we use Seatbelt (sandbox-exec + SBPL). sandbox-exec is marked
// deprecated by Apple but is still the only user-space way to apply an ad-hoc
// profile, and it is what Chrome, the App Sandbox and many tools still rely on
// under the hood. The profile is deny-by-default; we open up only what an
// interpreter-based harness needs.
package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"guard/internal/policy"
)

// SBPL string literals must be escaped. Paths with quotes/backslashes are
// rejected rather than escaped, to keep the generator honest.
func sbStr(p string) (string, error) {
	if strings.ContainsAny(p, "\"\\\n") {
		return "", fmt.Errorf("path %q contains characters unsafe for SBPL", p)
	}
	return `"` + p + `"`, nil
}

// Profile renders an SBPL profile from the policy. It is returned (not just
// executed) so guard can print it with --dry-run for human review.
func Profile(r *policy.Resolved) (string, error) {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w(";; guard: auto-generated Seatbelt profile — do not edit by hand")
	w("(version 1)")
	w("(deny default)")
	w("")

	// Process model: the harness spawns shells, node, python, MCP servers.
	// Tool filtering: restrict which executables ("tools") the agent may run.
	w(";; process / tool execution")
	w("(allow process-fork)")
	w("(allow signal (target self))")
	w("(allow process-info* (target self) (target children))")
	w("(allow sysctl-read)")
	if len(r.ExecAllow) > 0 {
		// Allowlist mode: deny all exec, then permit only the listed tools.
		w("(deny process-exec*)")
		for _, path := range r.ExecAllow {
			s, err := sbStr(path)
			if err != nil {
				return "", err
			}
			w("(allow process-exec* (literal %s))", s)
		}
	} else {
		// Denylist mode: allow exec generally, refuse the dangerous tools.
		w("(allow process-exec)")
		for _, path := range r.ExecDeny {
			s, err := sbStr(path)
			if err != nil {
				return "", err
			}
			w("(deny process-exec* (literal %s))", s)
		}
	}
	w("")

	// Reads: allow broadly so dynamic linking and interpreters work, then carve
	// out the secret paths. A later matching rule wins in SBPL, so the denies
	// below override the blanket allow.
	w(";; filesystem reads")
	w("(allow file-read* file-read-metadata)")
	for _, d := range r.ReadDeny {
		s, err := sbStr(d)
		if err != nil {
			return "", err
		}
		w("(deny file-read* file-read-metadata (subpath %s))", s)
	}
	w("")

	// Writes: deny by default; allow workspace + extra writable + tmp/dev noise.
	w(";; filesystem writes")
	for _, path := range r.Writable {
		s, err := sbStr(path)
		if err != nil {
			return "", err
		}
		w("(allow file-write* (subpath %s))", s)
	}
	for _, extra := range []string{"/private/tmp", "/private/var/tmp", os.TempDir()} {
		s, err := sbStr(strings.TrimRight(extra, "/"))
		if err != nil {
			return "", err
		}
		w("(allow file-write* (subpath %s))", s)
	}
	w(`(allow file-write-data (literal "/dev/null") (literal "/dev/dtracehelper"))`)
	w(`(allow file-ioctl (literal "/dev/null") (literal "/dev/tty"))`)
	w(`(allow file-write* file-read* (regex #"^/dev/(tty|ptmx|null|zero|random|urandom)"))`)
	w("")

	// Self-protection: persistence surfaces inside writable dirs. These denies
	// come AFTER the writable allows, so they win.
	w(";; self-protection (block persistence even inside the workspace)")
	for _, sp := range r.SelfProtect {
		s, err := sbStr(sp)
		if err != nil {
			return "", err
		}
		w("(deny file-write* (subpath %s))", s)
		w("(deny file-write* (literal %s))", s)
	}
	w("")

	// Network: only the loopback proxy. Everything else is denied, so the agent
	// cannot exfiltrate directly — it must go through guard's allowlisted proxy.
	w(";; network — loopback only (the guard egress proxy)")
	w(`(allow network-outbound (remote ip "localhost:*"))`)
	w(`(allow network-bind (local ip "localhost:*"))`)
	w(`(allow system-socket)`)
	w("")

	// IPC: a blanket mach-lookup is too broad (Keychain, AppleEvents). Allow the
	// handful of services an interpreter needs; deny the dangerous ones loudly.
	w(";; IPC — narrow mach services")
	for _, svc := range []string{
		"com.apple.system.notification_center",
		"com.apple.system.logger",
		"com.apple.system.opendirectoryd.libinfo",
		"com.apple.dnssd.service",
		"com.apple.coreservices.launchservicesd",
	} {
		w(`(allow mach-lookup (global-name "%s"))`, svc)
	}
	for _, svc := range []string{
		"com.apple.securityd",
		"com.apple.SecurityServer",
		"com.apple.coreservices.appleevents",
	} {
		w(`(deny mach-lookup (global-name "%s"))`, svc)
	}
	w("(allow ipc-posix-shm)")
	w("")

	return b.String(), nil
}

// Command builds the exec.Cmd that runs argv under the generated profile.
// profilePath is a file guard has already written with Profile()'s output.
func Command(profilePath string, env []string, argv []string) *exec.Cmd {
	full := append([]string{"-f", profilePath}, argv...)
	cmd := exec.Command("/usr/bin/sandbox-exec", full...)
	cmd.Env = env
	return cmd
}

// Backend names the confinement mechanism, for logging.
func Backend() string { return "seatbelt (sandbox-exec)" }
