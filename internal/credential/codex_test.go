package credential

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCache(t *testing.T, home, access string) {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"tokens": map[string]string{"access_token": access, "account_id": "fixture-account", "refresh_token": "fixture-refresh", "id_token": "fixture-id"}})
	if err := os.WriteFile(filepath.Join(home, "auth.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestCredentialHeadersReload(t *testing.T) {
	home := t.TempDir()
	writeCache(t, home, "fixture-access")
	p, err := New(Config{Type: "codex", CodexHome: home})
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Headers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("Authorization") != "Bearer fixture-access" || h.Get("ChatGPT-Account-ID") != "fixture-account" {
		t.Fatal("missing auth headers")
	}
	writeCache(t, home, "rotated-access")
	h, err = p.Headers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("Authorization") != "Bearer rotated-access" {
		t.Fatal("credential rotation was not picked up")
	}
}
func TestCredentialRefreshUsesCodexRPC(t *testing.T) {
	home := t.TempDir()
	payload, _ := json.Marshal(map[string]int64{"exp": time.Now().Add(-time.Hour).Unix()})
	expired := "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
	writeCache(t, home, expired)
	helper := filepath.Join(home, "fake-codex")
	script := `#!/bin/sh
while IFS= read -r line; do
 case "$line" in
  *'"method":"initialize"'*) printf '%s\n' '{"id":1,"result":{}}' ;;
  *'"method":"account/read"'*)
   printf '%s\n' '{"tokens":{"access_token":"refreshed-access","account_id":"fixture-account"}}' > "$CODEX_HOME/auth.json"
   printf '%s\n' '{"id":2,"result":{"account":{"type":"chatgpt"}}}' ;;
 esac
done
`
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Type: "codex", CodexHome: home, Binary: helper})
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Headers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("Authorization") != "Bearer refreshed-access" {
		t.Fatal("refreshed token not used")
	}
}
func TestMissingLoginDoesNotExposeCache(t *testing.T) {
	if _, err := New(Config{Type: "codex", CodexHome: t.TempDir()}); err == nil {
		t.Fatal("missing login accepted")
	}
}
