//go:build linux

// Linux backend: bubblewrap (bwrap). This is "chroot done right" — a mount +
// pid + net namespace. The root filesystem is bind-mounted read-only, the
// workspace read-write, HOME is a throwaway tmpfs, and the network namespace is
// unshared so the ONLY reachable endpoint is the guard proxy on loopback.
package sandbox

import (
	"os"
	"os/exec"

	"guard/internal/policy"
)

// Profile returns the bwrap argument vector as a human-readable string for
// --dry-run review. (On Linux there is no SBPL text; this is the arg list.)
func Profile(r *policy.Resolved) (string, error) {
	args := bwrapArgs(r)
	out := "bwrap \\\n"
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			out += "  " + args[i] + " " + args[i+1] + " \\\n"
		} else {
			out += "  " + args[i] + " \\\n"
		}
	}
	return out, nil
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
