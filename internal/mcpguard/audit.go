package mcpguard

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type event struct {
	Time          time.Time `json:"time"`
	Session       string    `json:"session"`
	ID            string    `json:"call_id,omitempty"`
	Server        string    `json:"server,omitempty"`
	Tool          string    `json:"tool,omitempty"`
	Type          string    `json:"type"`
	Decision      string    `json:"decision,omitempty"`
	Rule          string    `json:"rule,omitempty"`
	ArgumentsHash string    `json:"arguments_hash,omitempty"`
	SchemaHash    string    `json:"schema_hash,omitempty"`
	DurationMS    int64     `json:"duration_ms,omitempty"`
	Bytes         int       `json:"bytes,omitempty"`
}
type audit struct {
	mu      sync.Mutex
	file    *os.File
	session string
	err     error
}

func newAudit(path string) (*audit, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, fmt.Errorf("MCP audit log must be a private regular file (0600)")
	}
	return &audit{file: f, session: randomID()}, nil
}
func (a *audit) write(e event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	e.Server = label(e.Server, 64)
	e.Tool = label(e.Tool, 128)
	e.Rule = label(e.Rule, 256)
	e.Time = time.Now().UTC()
	e.Session = a.session
	a.err = json.NewEncoder(a.file).Encode(e)
	return a.err
}
func (a *audit) close() error { a.mu.Lock(); defer a.mu.Unlock(); return a.file.Close() }

func label(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
