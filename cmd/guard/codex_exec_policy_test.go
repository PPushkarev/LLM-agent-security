package main

import (
	"guard/internal/policy"
	"os"
	"path/filepath"
	"testing"
)

func TestCodexStagingHonorsExecutionPolicy(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	base := func() *policy.Resolved {
		return &policy.Resolved{Workspace: t.TempDir(), Raw: policy.Policy{Codex: policy.Codex{Binary: exe}}, KeyInject: []policy.KeyInjection{{Prefix: "/openai", Upstream: "https://api.openai.com"}}}
	}
	r := base()
	r.ExecDeny = []string{exe}
	if _, _, _, err := prepareCodex(r, 12345, nil, ""); err == nil {
		t.Fatal("staging bypassed exec.deny")
	}
	r = base()
	r.ExecAllow = []string{"/unlisted/binary"}
	if _, _, _, err := prepareCodex(r, 12345, nil, ""); err == nil {
		t.Fatal("staging bypassed exec.allow")
	}
	r = base()
	r.ExecAllow = []string{exe}
	argv, _, cleanup, err := prepareCodex(r, 12345, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	allowed := false
	for _, path := range r.ExecAllow {
		if path == argv[0] {
			allowed = true
		}
	}
	if !allowed {
		t.Fatal("approved original executable lost permission during staging")
	}
}
