//go:build darwin

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"guard/internal/policy"
)

func TestAttackAcceptance(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	ws := filepath.Join(root, "ws")
	for _, dir := range []string{home, ws, filepath.Join(ws, ".git", "hooks")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	var denies []string
	for _, name := range []string{".ssh", ".aws", ".codex", ".claude", ".hermes"} {
		p := filepath.Join(home, name)
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "fixture"), []byte("fake secret"), 0600); err != nil {
			t.Fatal(err)
		}
		denies = append(denies, p)
	}
	t.Setenv("HOME", home)
	t.Setenv("OPENAI_API_KEY", "fake-test-secret")
	t.Setenv("GITHUB_TOKEN", "fake-test-secret")
	p := policy.Policy{Workspace: ws, ReadDeny: denies, SelfProtect: []string{".git/hooks", ".envrc"}, EnvAllow: []string{"PATH", "HOME"}, Exec: policy.ExecPolicy{Deny: []string{"/usr/bin/ssh", "/usr/bin/sudo", "/usr/bin/nc", "/usr/bin/security", "/usr/bin/osascript"}}}
	data, _ := json.Marshal(p)
	path := filepath.Join(root, "policy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../attack/attack.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := runLaunch(r, false, []string{"/bin/sh", script}, strings.NewReader(""), false); err != nil {
		t.Fatal(err)
	}
}
