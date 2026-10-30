// Package guardrails implements session-wide controls independently of harness
// protocol. Content and MCP policies remain at their respective proxy boundaries.
package guardrails

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Config struct {
	Strict            bool   `json:"strict"`
	MaxSessionSeconds int    `json:"max_session_seconds"`
	MaxOutputBytes    int64  `json:"max_output_bytes"`
	AuditLog          string `json:"audit_log"`
}
type Session struct {
	mu       sync.Mutex
	cfg      Config
	file     *os.File
	id       string
	bytes    int64
	closed   bool
	reason   string
	err      error
	violated chan struct{}
	timer    *time.Timer
}

func New(cfg Config) (*Session, error) {
	if cfg.MaxSessionSeconds < 0 || cfg.MaxOutputBytes < 0 {
		return nil, fmt.Errorf("guardrail limits must not be negative")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	s := &Session{cfg: cfg, id: hex.EncodeToString(id), violated: make(chan struct{})}
	if cfg.AuditLog != "" {
		if st, err := os.Lstat(cfg.AuditLog); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("guardrail audit must not be a symlink")
		}
		f, err := os.OpenFile(cfg.AuditLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			f.Close()
			return nil, fmt.Errorf("guardrail audit must be a private regular file (0600)")
		}
		s.file = f
	}
	if err := s.eventLocked("session_start", ""); err != nil {
		if s.file != nil {
			s.file.Close()
		}
		return nil, err
	}
	return s, nil
}
func (s *Session) eventLocked(event, reason string) error {
	if s.err != nil {
		return s.err
	}
	if s.file == nil {
		return nil
	}
	s.err = json.NewEncoder(s.file).Encode(struct {
		Time        time.Time `json:"time"`
		Session     string    `json:"session"`
		Event       string    `json:"event"`
		Reason      string    `json:"reason,omitempty"`
		OutputBytes int64     `json:"output_bytes"`
	}{time.Now().UTC(), s.id, event, reason, s.bytes})
	return s.err
}
func (s *Session) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxSessionSeconds > 0 {
		s.timer = time.AfterFunc(time.Duration(s.cfg.MaxSessionSeconds)*time.Second, func() { s.mu.Lock(); defer s.mu.Unlock(); s.stopLocked("max_session_seconds") })
	}
}
func (s *Session) stopLocked(reason string) {
	if s.reason != "" || s.closed {
		return
	}
	s.reason = reason
	_ = s.eventLocked("session_block", reason)
	close(s.violated)
}
func (s *Session) Violated() <-chan struct{} { return s.violated }
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return fmt.Errorf("guardrail audit: %w", s.err)
	}
	if s.reason != "" {
		return fmt.Errorf("guardrail blocked session: %s", s.reason)
	}
	return nil
}
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.err
	}
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	err := s.eventLocked("session_end", s.reason)
	if s.file != nil {
		if e := s.file.Close(); err == nil {
			err = e
		}
	}
	return err
}

type output struct {
	s   *Session
	dst io.Writer
}

func (s *Session) Output(dst io.Writer) io.Writer { return output{s, dst} }
func (w output) Write(p []byte) (int, error) {
	w.s.mu.Lock()
	if w.s.reason != "" || w.s.closed {
		w.s.mu.Unlock()
		return 0, fmt.Errorf("session stopped by guardrail")
	}
	allowed := len(p)
	exceeded := false
	if max := w.s.cfg.MaxOutputBytes; max > 0 && int64(allowed) > max-w.s.bytes {
		allowed = int(max - w.s.bytes)
		exceeded = true
	}
	// Reserve bytes before releasing the lock so stdout/stderr share one budget.
	w.s.bytes += int64(allowed)
	if exceeded {
		w.s.stopLocked("max_output_bytes")
	}
	w.s.mu.Unlock()
	// A blocked output consumer must not prevent the timeout callback from firing.
	n, err := w.dst.Write(p[:allowed])
	if err != nil {
		return n, err
	}
	if exceeded {
		return n, fmt.Errorf("guardrail output limit exceeded")
	}
	return n, nil
}
