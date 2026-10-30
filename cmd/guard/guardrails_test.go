package main

import (
	"guard/internal/guardrails"
	"guard/internal/policy"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLaunchSessionGuardrails(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("OS sandbox")
	}
	for _, tc := range []struct {
		name, command, reason string
		seconds               int
		bytes                 int64
	}{
		{"timeout", "sleep 30", "max_session_seconds", 1, 0},
		{"output", "printf 123456789; sleep 30", "max_output_bytes", 0, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := filepath.EvalSymlinks(t.TempDir())
			ws := filepath.Join(root, "ws")
			os.Mkdir(ws, 0700)
			audit := filepath.Join(root, "session.jsonl")
			r := &policy.Resolved{Workspace: ws, Writable: []string{ws}, EnvAllow: map[string]bool{"PATH": true}, Guardrails: guardrails.Config{MaxSessionSeconds: tc.seconds, MaxOutputBytes: tc.bytes, AuditLog: audit}}
			start := time.Now()
			err := runLaunch(r, false, []string{"/bin/sh", "-c", tc.command}, strings.NewReader(""), false)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("expected %s: %v", tc.reason, err)
			}
			if time.Since(start) > 5*time.Second {
				t.Fatal("harness or descendants survived guardrail")
			}
			b, err := os.ReadFile(audit)
			if err != nil || !strings.Contains(string(b), tc.reason) || !strings.Contains(string(b), "session_end") {
				t.Fatalf("audit: %s, %v", b, err)
			}
		})
	}
}
