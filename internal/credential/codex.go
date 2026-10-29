// Package credential reads and refreshes Codex credentials in the trusted parent.
package credential

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Type      string `json:"type"`
	CodexHome string `json:"codex_home"`
	Binary    string `json:"binary"`
}

type Provider struct {
	home, binary string
	mu           sync.Mutex
}
type cache struct {
	Tokens struct {
		Access  string `json:"access_token"`
		Account string `json:"account_id"`
		Refresh string `json:"refresh_token"`
		ID      string `json:"id_token"`
	} `json:"tokens"`
}

func New(cfg Config) (*Provider, error) {
	if cfg.Type != "codex" {
		return nil, fmt.Errorf("unsupported credential type %q", cfg.Type)
	}
	home := cfg.CodexHome
	if home == "" {
		home = os.Getenv("CODEX_HOME")
	}
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		home = filepath.Join(h, ".codex")
	}
	var err error
	home, err = filepath.Abs(home)
	if err != nil {
		return nil, err
	}
	binary := cfg.Binary
	if binary == "" {
		binary = "codex"
	}
	p := &Provider{home: home, binary: binary}
	if _, err := p.read(); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *Provider) Home() string { return p.home }
func (p *Provider) read() (cache, error) {
	var c cache
	fh, err := os.Open(filepath.Join(p.home, "auth.json"))
	if err != nil {
		return c, fmt.Errorf("Codex login cache unavailable; run codex -c cli_auth_credentials_store=\"file\" login outside guard")
	}
	defer fh.Close()
	if err := json.NewDecoder(io.LimitReader(fh, 1<<20)).Decode(&c); err != nil {
		return c, fmt.Errorf("invalid Codex login cache")
	}
	if c.Tokens.Access == "" || c.Tokens.Account == "" {
		return c, fmt.Errorf("ChatGPT login required; run codex login outside guard")
	}
	return c, nil
}
func expiresSoon(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var v struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(data, &v) != nil || v.Exp == 0 {
		return false
	}
	return time.Unix(v.Exp, 0).Before(time.Now().Add(2 * time.Minute))
}

// Headers reloads the cache and refreshes expiring tokens through Codex's own
// account/read RPC. Tokens never enter the sandbox or command-line arguments.
func (p *Provider) Headers(ctx context.Context) (http.Header, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, err := p.read()
	if err != nil {
		return nil, err
	}
	if expiresSoon(c.Tokens.Access) {
		if err := p.refresh(ctx); err != nil {
			return nil, err
		}
		c, err = p.read()
		if err != nil {
			return nil, err
		}
		if expiresSoon(c.Tokens.Access) {
			return nil, fmt.Errorf("Codex login is expired; run codex login outside guard")
		}
	}
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+c.Tokens.Access)
	h.Set("ChatGPT-Account-ID", c.Tokens.Account)
	return h, nil
}
func (p *Provider) refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// This trusted helper only handles account auth. No thread or model turn is created.
	cmd := exec.CommandContext(ctx, p.binary, "-c", `cli_auth_credentials_store="file"`, "app-server", "--listen", "stdio://")
	cmd.Dir = os.TempDir()
	cmd.Env = append(os.Environ(), "CODEX_HOME="+p.home)
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("cannot start Codex credential refresh")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("cannot start Codex credential refresh")
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start Codex credential refresh")
	}
	defer func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() }()
	encoder := json.NewEncoder(stdin)
	if err := encoder.Encode(map[string]any{"id": 1, "method": "initialize", "params": map[string]any{"clientInfo": map[string]string{"name": "guard_auth", "version": "1.0"}}}); err != nil {
		return fmt.Errorf("Codex credential refresh failed")
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	wait := func(id int) error {
		for scanner.Scan() {
			var response struct {
				ID    *int            `json:"id"`
				Error json.RawMessage `json:"error"`
			}
			if json.Unmarshal(scanner.Bytes(), &response) != nil {
				continue
			}
			if response.ID != nil && *response.ID == id {
				if len(response.Error) > 0 && string(response.Error) != "null" {
					return fmt.Errorf("Codex rejected credential refresh; run codex login outside guard")
				}
				return nil
			}
		}
		return fmt.Errorf("Codex credential refresh ended before a response")
	}
	if err := wait(1); err != nil {
		return err
	}
	if err := encoder.Encode(map[string]any{"method": "initialized"}); err != nil {
		return fmt.Errorf("Codex credential refresh failed")
	}
	if err := encoder.Encode(map[string]any{"id": 2, "method": "account/read", "params": map[string]bool{"refreshToken": true}}); err != nil {
		return fmt.Errorf("Codex credential refresh failed")
	}
	return wait(2)
}

// Secrets returns credentials only to trusted initialization code, never to the child.
func (p *Provider) Secrets() ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, err := p.read()
	if err != nil {
		return nil, err
	}
	return []string{c.Tokens.Access, c.Tokens.Refresh, c.Tokens.ID}, nil
}
