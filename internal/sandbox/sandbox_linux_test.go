//go:build linux

package sandbox

import (
	"fmt"
	"guard/internal/policy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxProfileReady(t *testing.T) {
	if _, err := Profile(&policy.Resolved{Workspace: "/tmp", Writable: []string{"/tmp"}}); err != nil {
		t.Fatalf("Linux cannot launch a sandbox: %v", err)
	}
}

func TestLinuxSandboxFixture(t *testing.T) {
	if os.Getenv("GUARD_LINUX_FIXTURE") != "1" {
		return
	}
	fail := func(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
	if _, err := os.ReadFile(os.Getenv("GUARD_SECRET")); err == nil {
		fail(fmt.Errorf("secret readable"))
	}
	if err := os.WriteFile(os.Getenv("GUARD_OUTSIDE"), []byte("escape"), 0600); err == nil {
		fail(fmt.Errorf("outside write allowed"))
	}
	if err := os.WriteFile("allowed.txt", []byte("ok"), 0600); err != nil {
		fail(err)
	}
	if c, err := net.DialTimeout("tcp", os.Getenv("GUARD_NEIGHBOR"), time.Second); err == nil {
		c.Close()
		fail(fmt.Errorf("host TCP reachable"))
	}
	if c, err := net.DialTimeout("unix", os.Getenv("GUARD_SOCKET"), time.Second); err == nil {
		c.Close()
		fail(fmt.Errorf("host Unix socket reachable"))
	}
	if err := exec.Command("/bin/sh", "-c", "true").Run(); err == nil {
		fail(fmt.Errorf("denied executable ran"))
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for i := 0; i < 3; i++ {
		res, err := c.Get(os.Getenv("GUARD_PROXY"))
		if err != nil {
			fail(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if string(b) != "PROXY_OK" {
			fail(fmt.Errorf("proxy response: %s", b))
		}
	}
	os.Exit(0)
}
func TestLinuxIsolationAndProxy(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "workspace")
	os.Mkdir(ws, 0700)
	t.Setenv("HOME", root)
	secretDir := filepath.Join(ws, "private")
	os.Mkdir(secretDir, 0700)
	secret := filepath.Join(secretDir, "secret")
	os.WriteFile(secret, []byte("private"), 0600)
	socketPath := filepath.Join(ws, "host.sock")
	socket, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	neighbor, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer neighbor.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "PROXY_OK") }))
	defer proxy.Close()
	port := proxy.Listener.Addr().(*net.TCPAddr).Port
	r := &policy.Resolved{Workspace: ws, Writable: []string{ws}, ReadDeny: []string{secret, secretDir}, ExecDeny: []string{"/bin/sh"}, ProxyPort: port}
	exe, _ := os.Executable()
	env := []string{"GUARD_LINUX_FIXTURE=1", "GUARD_SECRET=" + secret, "GUARD_OUTSIDE=/etc/guard-test-escape", "GUARD_NEIGHBOR=" + neighbor.Addr().String(), "GUARD_SOCKET=" + socketPath, "GUARD_PROXY=" + proxy.URL}
	cmd, cleanup, err := CommandFor(r, env, []string{exe, "-test.run=^TestLinuxSandboxFixture$"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sandbox: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(ws, "allowed.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxExecutionAllowlist(t *testing.T) {
	ws := t.TempDir()
	exe, _ := os.Executable()
	r := &policy.Resolved{Workspace: ws, Writable: []string{ws}, ExecAllow: []string{exe}}
	cmd, cleanup, err := CommandFor(r, []string{}, []string{exe, "-test.run=^$"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := cmd.CombinedOutput()
	cleanup()
	if err != nil {
		t.Fatalf("Landlock allowed execution failed: %v\n%s", err, b)
	}
	cmd, cleanup, err = CommandFor(r, []string{}, []string{"/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if b, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("unlisted executable ran: %s", b)
	}
}
func TestLinuxMissingProtection(t *testing.T) {
	ws := t.TempDir()
	protected := filepath.Join(ws, "new", "config")
	r := &policy.Resolved{Workspace: ws, Writable: []string{ws}, SelfProtect: []string{protected}}
	cmd, cleanup, err := CommandFor(r, []string{}, []string{"/bin/sh", "-c", `echo ok > allowed; if echo bypass > new/config; then exit 42; fi`})
	if err != nil {
		t.Fatal(err)
	}
	b, err := cmd.CombinedOutput()
	cleanup()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if _, err := os.Stat(filepath.Join(ws, "allowed")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(protected); !os.IsNotExist(err) {
		t.Fatalf("placeholder not removed: %v", err)
	}
}
