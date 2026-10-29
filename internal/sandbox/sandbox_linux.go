//go:build linux

// Linux backend is disabled until its network namespace has a transport to
// the trusted parent proxy. The argument builder is retained for that work;
// Profile fails closed so callers cannot mistake it for a usable sandbox.
package sandbox

import (
	"fmt"
	"os"
	"os/exec"

	"guard/internal/policy"
)

// Profile returns the bwrap argument vector as a human-readable string for
// --dry-run review. (On Linux there is no SBPL text; this is the arg list.)
func Profile(r *policy.Resolved) (string, error) {
	return "", fmt.Errorf("Linux backend is not ready: isolated proxy transport is not implemented; use macOS Seatbelt")
}

func bwrapArgs(r *policy.Resolved) []string {
	a := []string{
		"--ro-bind", "/", "/", // whole FS read-only…
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--unshare-all", // new user/pid/net/ipc/uts/mount namespaces (net included)
		"--die-with-parent",
		"--new-session",
	}
	// Secrets: mask with empty tmpfs so even the blanket ro-bind can't read them.
	for _, d := range r.ReadDeny {
		a = append(a, "--tmpfs", d)
	}
	// Writable paths rebind rw on top of the ro root.
	for _, w := range r.Writable {
		a = append(a, "--bind", w, w)
	}
	// Self-protected paths rebind ro on top of the writable workspace.
	for _, sp := range r.SelfProtect {
		if _, err := os.Stat(sp); err == nil {
			a = append(a, "--ro-bind", sp, sp)
		}
	}
	// HOME becomes a throwaway tmpfs so rc-file persistence is lost on exit.
	if home, err := os.UserHomeDir(); err == nil {
		a = append(a, "--tmpfs", home)
	}
	return a
}

// Command builds the exec.Cmd. profilePath is unused on Linux (kept for a
// uniform signature with darwin); the args come straight from the policy.
func Command(_ string, env []string, argv []string) *exec.Cmd {
	// NOTE: the resolved policy is threaded in via the caller on Linux by
	// prepending bwrap args; see run.go. Here we assume argv already starts with
	// the bwrap invocation produced by CommandFor.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	return cmd
}

// CommandFor is the Linux-specific builder that the runner uses.
func CommandFor(r *policy.Resolved, env []string, argv []string) *exec.Cmd {
	full := append(bwrapArgs(r), argv...)
	cmd := exec.Command("bwrap", full...)
	cmd.Env = env
	return cmd
}

func Backend() string { return "bubblewrap (bwrap)" }
