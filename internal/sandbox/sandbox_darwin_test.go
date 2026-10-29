//go:build darwin

package sandbox

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"guard/internal/policy"
)

func TestProxyPortIsolation(t *testing.T) {
	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer allowed.Close()
	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "unexpected") }))
	defer denied.Close()
	port, _ := strconv.Atoi(strings.TrimPrefix(allowed.URL, "http://127.0.0.1:"))
	r := &policy.Resolved{ProxyPort: port}
	profile, err := Profile(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(profile, "localhost:*") {
		t.Fatal("unrestricted loopback")
	}
	path := filepath.Join(t.TempDir(), "profile.sb")
	if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec unavailable")
	}
	for _, tc := range []struct {
		url     string
		allowed bool
	}{{allowed.URL, true}, {denied.URL, false}} {
		cmd := Command(path, []string{"PATH=/usr/bin:/bin"}, []string{"/usr/bin/curl", "--noproxy", "*", "-fsS", "--max-time", "3", tc.url})
		out, err := cmd.CombinedOutput()
		if (err == nil) != tc.allowed {
			t.Fatalf("%s: err=%v output=%s", tc.url, err, out)
		}
	}
}

func TestOfflineProfile(t *testing.T) {
	profile, err := Profile(&policy.Resolved{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(profile, "(allow network-outbound") {
		t.Fatal("port zero permits outbound")
	}
}
