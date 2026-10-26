// Command guard runs an arbitrary agent harness (Claude Code, Codex, Hermes,
// or any other) inside an OS-level sandbox with an allowlisting egress proxy.
//
//	guard run --policy policy.json -- <harness> [args...]
//	guard run --policy policy.json --dry-run -- <harness> [args...]
//
// The harness and every child it spawns inherit: a deny-by-default filesystem,
// loopback-only networking that forces traffic through guard's proxy, a
// scrubbed environment with no secrets, and write-protection on persistence
// surfaces inside the workspace.
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"guard/internal/filter"
	"guard/internal/policy"
	"guard/internal/proxy"
	"guard/internal/sandbox"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:])
	case "submit":
		submitCmd(os.Args[2:])
	case "profile":
		profileCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `guard — sandbox any agent harness

usage:
  guard run     --policy FILE [--dry-run] -- HARNESS [ARGS...]
  guard submit  --policy FILE [--prompt TEXT] [-- HARNESS ARGS...]
                filter a prompt (block/mask) before the harness sees it
  guard profile --policy FILE          print the generated sandbox profile

`)
	os.Exit(2)
}

func parseArgs(args []string) (policyPath string, dryRun bool, argv []string) {
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--policy":
			i++
			if i >= len(args) {
				die("--policy needs a value")
			}
			policyPath = args[i]
		case "--dry-run":
			dryRun = true
		case "--":
			argv = args[i+1:]
			return
		default:
			die("unknown flag %q", args[i])
		}
		i++
	}
	return
}

// submitCmd is Filter A: it inspects the prompt BEFORE the harness ever sees
// it. Forbidden content is cut off (block → the prompt is refused) and
// unnecessary/sensitive spans are masked (redact). Without a `--` harness it
// prints the cleaned prompt; with one, it runs the harness sandboxed and feeds
// the cleaned prompt on stdin.
func submitCmd(args []string) {
	// Pull an optional --prompt out, keep the rest for parseArgs.
	var promptArg string
	havePrompt := false
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--prompt" {
			if i+1 >= len(args) {
				die("--prompt needs a value")
			}
			promptArg, havePrompt = args[i+1], true
			i++
			continue
		}
		if args[i] == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		rest = append(rest, args[i])
	}
	policyPath, _, argv := parseArgs(rest)
	if policyPath == "" {
		die("--policy is required")
	}
	r, err := policy.Load(policyPath)
	if err != nil {
		die("%v", err)
	}

	var prompt []byte
	if havePrompt {
		prompt = []byte(promptArg)
	} else {
		prompt, _ = io.ReadAll(os.Stdin) // prompt piped on stdin
	}

	f, err := filter.New(r.PromptFilter)
	if err != nil {
		die("filter: %v", err)
	}
	defer f.Close()
	cleaned, d := f.Request(prompt)

	logger := log.New(os.Stderr, "\x1b[2m[guard]\x1b[0m ", 0)
	if len(d.Flagged) > 0 {
		logger.Printf("input FLAG rules=%s (prompt kept as written)", strings.Join(d.Flagged, ","))
	}
	switch d.Action {
	case filter.Block:
		// "отсечь": the prompt is refused and never reaches the harness.
		logger.Printf("input BLOCKED rule=%s — prompt refused, harness not invoked", d.Rule)
		die("prompt rejected by guard input filter: %s", d.Rule)
	case filter.Redact:
		logger.Printf("\x1b[33minput REDACT: masked %d span(s) (rule=%s) before the harness sees it\x1b[0m", d.Count, d.Rule)
	}

	if len(argv) == 0 {
		// No harness: emit the cleaned prompt for inspection or piping.
		os.Stdout.Write(cleaned)
		if len(cleaned) > 0 && cleaned[len(cleaned)-1] != '\n' {
			fmt.Println()
		}
		return
	}
	launch(r, false, argv, bytes.NewReader(cleaned))
}

func profileCmd(args []string) {
	p, _, _ := parseArgs(args)
	if p == "" {
		die("--policy is required")
	}
	r, err := policy.Load(p)
	if err != nil {
		die("%v", err)
	}
	text, err := sandbox.Profile(r)
	if err != nil {
		die("%v", err)
	}
	fmt.Print(text)
}

func runCmd(args []string) {
	policyPath, dryRun, argv := parseArgs(args)
	if policyPath == "" {
		die("--policy is required")
	}
	if len(argv) == 0 {
		die("nothing to run: put the harness command after --")
	}
	r, err := policy.Load(policyPath)
	if err != nil {
		die("%v", err)
	}
	launch(r, dryRun, argv, os.Stdin)
}

// launch sets up the proxy + sandbox and runs argv with the given stdin.
func launch(r *policy.Resolved, dryRun bool, argv []string, stdin io.Reader) {
	logger := log.New(os.Stderr, "\x1b[2m[guard]\x1b[0m ", 0)

	// 1. Start the egress proxy in the trusted parent (secrets live here only).
	px, err := proxy.New(r, logger)
	if err != nil {
		die("proxy: %v", err)
	}
	port, err := px.Start(r.ProxyPort)
	if err != nil {
		die("proxy listen: %v", err)
	}
	defer px.Close()
	defer px.CloseFilter()
	logger.Printf("backend=%s", sandbox.Backend())
	logger.Printf("workspace=%s", r.Workspace)
	logger.Printf("egress proxy on 127.0.0.1:%d (allow: %s)", port, strings.Join(r.AllowDomains, ", "))
	if r.PromptFilter.Enabled {
		mode := r.PromptFilter.Mode
		if mode == "" {
			mode = "enforce"
		}
		logger.Printf("prompt filter ON mode=%s (redact rules can modify prompts; monitor mode never alters)", mode)
	}
	if l := r.Limits; l.MaxRequests > 0 || l.RatePerMin > 0 || l.MaxRequestBytes > 0 {
		logger.Printf("limits ON (max_requests=%d rate_per_min=%d max_request_bytes=%d)", l.MaxRequests, l.RatePerMin, l.MaxRequestBytes)
	}

	// 2. Write the generated profile where the sandbox can read it.
	profText, err := sandbox.Profile(r)
	if err != nil {
		die("profile: %v", err)
	}
	profPath := filepath.Join(os.TempDir(), fmt.Sprintf("guard-%d.sb", os.Getpid()))
	if err := os.WriteFile(profPath, []byte(profText), 0600); err != nil {
		die("write profile: %v", err)
	}
	defer os.Remove(profPath)

	// 3. Build the scrubbed environment the child will see.
	env := buildEnv(r, port)

	if dryRun {
		fmt.Println("=== sandbox profile ===")
		fmt.Println(profText)
		fmt.Println("=== child environment ===")
		for _, e := range env {
			fmt.Println("  " + e)
		}
		fmt.Printf("=== would exec ===\n  %s\n", strings.Join(argv, " "))
		return
	}

	// 4. Launch the harness under the sandbox.
	cmd := buildCommand(r, profPath, env, argv)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, os.Stdout, os.Stderr

	// Forward signals so Ctrl-C reaches the harness.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sig {
			if cmd.Process != nil {
				cmd.Process.Signal(s)
			}
		}
	}()

	err = cmd.Run()
	logger.Printf("egress denials: %d · prompt-filter actions: %d · throttled: %d", px.DenyCount(), px.FilterCount(), px.LimitCount())
	if err != nil {
		if ee, ok := err.(*exitError); ok {
			os.Exit(ee.code)
		}
		if ee, ok := asExit(err); ok {
			os.Exit(ee)
		}
		die("run: %v", err)
	}
}

// buildEnv implements default-deny for the environment. Only names in
// env_allow pass through; guard then injects the proxy coordinates and points
// the harness's LLM base URLs at the loopback proxy, so the harness works
// without ever holding a key.
func buildEnv(r *policy.Resolved, port int) []string {
	var env []string
	for _, kv := range os.Environ() {
		name := kv[:strings.IndexByte(kv, '=')]
		if r.EnvAllow[name] {
			env = append(env, kv)
		}
	}
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	env = append(env,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"GUARD_PROXY="+proxyURL,
		"GUARD_SANDBOX=1",
	)
	// Point each key-injection route's base URL at the proxy prefix.
	for _, ki := range r.KeyInject {
		base := proxyURL + ki.Prefix
		switch {
		case strings.Contains(strings.ToLower(ki.Upstream), "anthropic"):
			env = append(env, "ANTHROPIC_BASE_URL="+base)
		case strings.Contains(strings.ToLower(ki.Upstream), "openai"):
			env = append(env, "OPENAI_BASE_URL="+base)
		}
		env = append(env, "GUARD_BASE_"+strings.ToUpper(strings.Trim(ki.Prefix, "/"))+"="+base)
	}
	return env
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "guard: "+format+"\n", a...)
	os.Exit(1)
}

type exitError struct{ code int }

func (e *exitError) Error() string { return "exit " + strconv.Itoa(e.code) }

func asExit(err error) (int, bool) {
	type coder interface{ ExitCode() int }
	if c, ok := err.(coder); ok {
		return c.ExitCode(), true
	}
	return 0, false
}
