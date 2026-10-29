package mcpguard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type Approval struct {
	CallID    string          `json:"call_id"`
	ID        string          `json:"id"`
	Session   string          `json:"session"`
	Server    string          `json:"server"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	Digest    string          `json:"digest"`
	Deadline  time.Time       `json:"deadline"`
}
type decision struct {
	Digest  string `json:"digest"`
	Approve bool   `json:"approve"`
}

var idRE = regexp.MustCompile(`^[a-f0-9]{32}$`)

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func digest(v []byte) string { sum := sha256.Sum256(v); return hex.EncodeToString(sum[:]) }

func requestApproval(ctx context.Context, dir string, a Approval) error {
	a.ID = randomID()
	// Bind approval to this exact session, tool and post-filter arguments.
	bound, _ := json.Marshal(a)
	a.Digest = digest(bound)
	path := filepath.Join(dir, a.ID+".json")
	b, _ := json.MarshalIndent(a, "", "  ")
	if err := writeExclusive(path, b); err != nil {
		return fmt.Errorf("approval queue unavailable")
	}
	defer os.Remove(path)
	decisionPath := filepath.Join(dir, a.ID+".decision")
	defer os.Remove(decisionPath)
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for {
		if time.Now().After(a.Deadline) {
			return fmt.Errorf("approval timed out")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		b, err := readRegular(decisionPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("invalid approval decision")
		}
		var d decision
		if json.Unmarshal(b, &d) != nil || d.Digest != a.Digest {
			return fmt.Errorf("approval does not match the request")
		}
		if !d.Approve {
			return fmt.Errorf("approval declined")
		}
		return nil
	}
}
func writeExclusive(path string, b []byte) error {
	// Rename a complete file, never expose a partially written JSON record.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Link is an atomic no-replace publish on the same filesystem.
	return os.Link(name, path)
}
func readRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxBytes {
		return nil, fmt.Errorf("unsafe approval file")
	}
	return os.ReadFile(path)
}
func Pending(dir string) ([]Approval, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []Approval{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Approval{}
	for _, e := range entries {
		if e.IsDir() || !idRE.MatchString(trimSuffix(e.Name(), ".json")) {
			continue
		}
		b, err := readRegular(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var a Approval
		if json.Unmarshal(b, &a) == nil && a.ID+".json" == e.Name() && a.Deadline.After(time.Now()) {
			out = append(out, a)
		}
	}
	return out, nil
}
func trimSuffix(s, suffix string) string {
	if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)]
	}
	return ""
}
func Decide(dir, id string, approve bool) error {
	if !idRE.MatchString(id) {
		return fmt.Errorf("invalid approval ID")
	}
	b, err := readRegular(filepath.Join(dir, id+".json"))
	if err != nil {
		return err
	}
	var a Approval
	if json.Unmarshal(b, &a) != nil || a.ID != id || !a.Deadline.After(time.Now()) {
		return fmt.Errorf("approval is invalid or expired")
	}
	b, _ = json.Marshal(decision{a.Digest, approve})
	return writeExclusive(filepath.Join(dir, id+".decision"), b)
}
