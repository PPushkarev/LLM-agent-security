package guardrails

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOutputBudgetAndAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := New(Config{MaxOutputBytes: 5, AuditLog: path})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if _, err := s.Output(&stdout).Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Output(&stderr).Write([]byte("SECRET")); err == nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if stdout.String()+stderr.String() != "abcSE" {
		t.Fatal("budget exceeded")
	}
	select {
	case <-s.Violated():
	default:
		t.Fatal("no stop notification")
	}
	if s.Err() == nil {
		t.Fatal("missing guardrail error")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("output leaked to audit")
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 {
		t.Fatalf("audit: %s", b)
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &event); err != nil {
		t.Fatal(err)
	}
	if event["reason"] != "max_output_bytes" {
		t.Fatal(event)
	}
}
func TestSessionTimeout(t *testing.T) {
	s, err := New(Config{MaxSessionSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Start()
	select {
	case <-s.Violated():
	case <-time.After(3 * time.Second):
		t.Fatal("session did not expire")
	}
	if err := s.Err(); err == nil || !strings.Contains(err.Error(), "max_session_seconds") {
		t.Fatal(err)
	}
}
func TestAuditFailureBlocks(t *testing.T) {
	s, err := New(Config{AuditLog: filepath.Join(t.TempDir(), "audit")})
	if err != nil {
		t.Fatal(err)
	}
	s.file.Close()
	if err := s.Close(); err == nil {
		t.Fatal("audit failure ignored")
	}
}
