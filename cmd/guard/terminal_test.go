package main

import (
	"github.com/creack/pty"
	"guard/internal/guardrails"
	"guard/internal/policy"
	"guard/internal/sandbox"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInteractiveHarnessKeepsTerminal(t *testing.T) {
	outer, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	defer slave.Close()
	session, err := guardrails.New(guardrails.Config{MaxOutputBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	r := &policy.Resolved{Workspace: root, Writable: []string{root}}
	profile, err := sandbox.Profile(r)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(root, "profile.sb")
	os.WriteFile(profilePath, []byte(profile), 0600)
	cmd, commandCleanup, err := buildCommand(r, profilePath, []string{"PATH=/usr/bin:/bin"}, []string{"/bin/sh", "-c", "test -t 0 && test -t 1 && stty -echo && printf TTY_OK"})
	if err != nil {
		t.Fatal(err)
	}
	defer commandCleanup()
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	read := make(chan string, 1)
	go func() { b := make([]byte, 6); _, _ = io.ReadFull(outer, b); read <- string(b) }()
	cleanup, err := startTerminalHarness(cmd, slave, slave, session, func(device string) error {
		r.TerminalDevice = device
		profile, err := sandbox.Profile(r)
		if err != nil {
			return err
		}
		return os.WriteFile(profilePath, []byte(profile), 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("interactive harness lost tty: %v", err)
	}
	cleanup()
	select {
	case text := <-read:
		if !strings.Contains(text, "TTY_OK") {
			t.Fatalf("missing terminal output: %q", text)
		}
	case <-time.After(time.Second):
		t.Fatal("no terminal output")
	}
}
