//go:build linux

package sandbox

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/sys/unix"
	"guard/internal/policy"
)

// The only connection crossing the network namespace is an inherited socketpair.
// Each multiplexed stream is connected to the trusted parent's own proxy port;
// the child never supplies an upstream address to this bridge.
const linuxHelper = "__guard_linux_sandbox_init"

type linuxConfig struct {
	Port      int
	ExecAllow []string
}

func Profile(r *policy.Resolved) (string, error) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return "", fmt.Errorf("Linux seccomp supports amd64 and arm64 only")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		return "", fmt.Errorf("Linux requires bubblewrap (install bubblewrap): %w", err)
	}
	return strings.Join(bwrapArgs(r), " ") + "\n# inherited proxy bridge; seccomp: no host Unix sockets, namespace changes or ptrace\n", nil
}
func bwrapArgs(r *policy.Resolved) []string {
	a := []string{"--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session", "--cap-drop", "ALL"}
	if len(r.ReadAllow) == 0 {
		a = append(a, "--ro-bind", "/", "/")
	} else {
		a = append(a, "--tmpfs", "/")
		paths := append([]string(nil), r.ReadAllow...)
		// The bridge helper must be readable even in a managed MCP's allowlist.
		if exe, err := os.Executable(); err == nil {
			paths = append(paths, exe)
		}
		sort.SliceStable(paths, func(i, j int) bool { return len(paths[i]) < len(paths[j]) })
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				a = append(a, "--ro-bind", p, p)
			}
		}
	}
	a = append(a, "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/run", "--tmpfs", "/var/tmp")
	// Mount parents first; denied reads are applied LAST so writable mounts cannot
	// accidentally reveal a secret. Do not hide HOME: workspace may live there.
	if len(r.ReadAllow) > 0 {
		visible := false
		for _, p := range r.ReadAllow {
			rel, err := filepath.Rel(p, r.Workspace)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
				visible = true
				break
			}
		}
		if !visible {
			a = append(a, "--tmpfs", r.Workspace, "--remount-ro", r.Workspace)
		}
	}
	paths := append([]string(nil), r.Writable...)
	sort.SliceStable(paths, func(i, j int) bool { return len(paths[i]) < len(paths[j]) })
	for _, p := range paths {
		a = append(a, "--bind", p, p)
	}
	if exe, err := os.Executable(); err == nil {
		a = append(a, "--ro-bind", exe, exe)
	}
	for _, p := range r.SelfProtect {
		if _, err := os.Stat(p); err == nil {
			a = append(a, "--ro-bind", p, p)
		}
	}

	denied := append(append([]string(nil), r.ReadDeny...), r.ExecDeny...)
	sort.SliceStable(denied, func(i, j int) bool { return len(denied[i]) < len(denied[j]) })
	var maskedDirs []string
	for _, p := range denied {
		if physical, err := filepath.EvalSymlinks(p); err == nil {
			p = physical
		}
		hidden := false
		for _, parent := range maskedDirs {
			rel, err := filepath.Rel(parent, p)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
				hidden = true
				break
			}
		}
		if hidden {
			continue
		}
		if st, err := os.Stat(p); err == nil {
			if st.IsDir() {
				maskedDirs = append(maskedDirs, p)
				a = append(a, "--tmpfs", p, "--remount-ro", p)
			} else {
				a = append(a, "--ro-bind", "/dev/null", p)
			}
		}
	}
	if len(r.ReadAllow) > 0 {
		a = append(a, "--remount-ro", "/")
	}
	return append(a, "--chdir", r.Workspace)
}
func muxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	c.AcceptBacklog = 64
	c.ConnectionWriteTimeout = 10 * time.Second
	return c
}
func CommandFor(r *policy.Resolved, env, argv []string) (*exec.Cmd, func(), error) {
	if _, err := Profile(r); err != nil {
		return nil, nil, err
	}
	protectedCleanup, err := prepareProtectedPaths(r)
	if err != nil {
		return nil, nil, err
	}
	success := false
	defer func() {
		if !success {
			protectedCleanup()
		}
	}()
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	parentFile := os.NewFile(uintptr(pair[0]), "guard-proxy-parent")
	childFile := os.NewFile(uintptr(pair[1]), "guard-proxy-child")
	conn, err := net.FileConn(parentFile)
	parentFile.Close()
	if err != nil {
		childFile.Close()
		return nil, nil, err
	}
	session, err := yamux.Server(conn, muxConfig())
	if err != nil {
		conn.Close()
		childFile.Close()
		return nil, nil, err
	}
	var once sync.Once
	cleanup := func() { once.Do(func() { childFile.Close(); session.Close(); protectedCleanup() }) }
	slots := make(chan struct{}, 64)
	go func() {
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				stream.Close()
				continue
			}
			go func() {
				defer func() { <-slots }()
				defer stream.Close()
				up, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.ProxyPort)), 5*time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				bridgeCopy(stream, up)
			}()
		}
	}()
	config, _ := json.Marshal(linuxConfig{Port: r.ProxyPort, ExecAllow: r.ExecAllow})
	args := append(bwrapArgs(r), "--", exe, linuxHelper, base64.RawStdEncoding.EncodeToString(config), "--")
	args = append(args, argv...)
	cmd := exec.Command("bwrap", args...)
	cmd.Env = env
	cmd.ExtraFiles = []*os.File{childFile}
	success = true
	return cmd, cleanup, nil
}
func bridgeCopy(a, b net.Conn) {
	done := make(chan struct{})
	go func() { io.Copy(a, b); a.Close(); close(done) }()
	io.Copy(b, a)
	b.Close()
	<-done
}
func init() {
	if len(os.Args) < 2 || os.Args[1] != linuxHelper {
		return
	}
	if err := linuxInit(); err != nil {
		fmt.Fprintln(os.Stderr, "guard Linux sandbox:", err)
		if e, ok := err.(*exec.ExitError); ok {
			os.Exit(e.ExitCode())
		}
		os.Exit(1)
	}
	os.Exit(0)
}
func linuxInit() error {
	if len(os.Args) < 5 || os.Args[3] != "--" {
		return fmt.Errorf("invalid sandbox helper invocation")
	}
	b, err := base64.RawStdEncoding.DecodeString(os.Args[2])
	if err != nil {
		return err
	}
	var cfg linuxConfig
	if err = json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	// Dup is CLOEXEC; neither the transport nor its original fd reaches harness.
	f := os.NewFile(3, "guard-proxy")
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return err
	}
	session, err := yamux.Client(conn, muxConfig())
	if err != nil {
		conn.Close()
		return err
	}
	defer session.Close()
	if cfg.Port > 0 {
		listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Port)))
		if err != nil {
			return err
		}
		defer listener.Close()
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					stream, err := session.OpenStream()
					if err != nil {
						return
					}
					defer stream.Close()
					bridgeCopy(c, stream)
				}()
			}
		}()
	}
	if err := installLinuxSeccomp(); err != nil {
		return fmt.Errorf("mandatory seccomp: %w", err)
	}
	cmd := exec.Command(os.Args[4], os.Args[5:]...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Landlock applies in a separate locked OS thread just before exec; see helper.
	if len(cfg.ExecAllow) > 0 {
		return runExecAllow(cmd, cfg.ExecAllow)
	}
	return cmd.Run()
}
func Backend() string { return "bubblewrap + isolated proxy bridge + seccomp" }

// Reserve absent protected paths for the session. A read-only mount on an
// existing ancestor would disable the entire workspace. Empty placeholders
// instead prevent creating persistence files without hiding project contents.
func prepareProtectedPaths(r *policy.Resolved) (func(), error) {
	type entry struct {
		path string
		info os.FileInfo
	}
	var created []entry
	cleanup := func() {
		for i := len(created) - 1; i >= 0; i-- {
			e := created[i]
			if st, err := os.Lstat(e.path); err == nil && os.SameFile(st, e.info) {
				if st.IsDir() || st.Size() == 0 {
					_ = os.Remove(e.path)
				}
			}
		}
	}
	for _, path := range r.SelfProtect {
		writable := false
		for _, w := range r.Writable {
			rel, err := filepath.Rel(w, path)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				writable = true
				break
			}
		}
		if !writable {
			continue
		}
		if _, err := os.Lstat(path); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			cleanup()
			return nil, err
		}
		var missing []string
		for p := filepath.Dir(path); p != "/"; p = filepath.Dir(p) {
			if _, err := os.Stat(p); err == nil {
				break
			}
			missing = append(missing, p)
		}
		for i := len(missing) - 1; i >= 0; i-- {
			p := missing[i]
			if err := os.Mkdir(p, 0700); err != nil {
				cleanup()
				return nil, err
			}
			st, _ := os.Lstat(p)
			created = append(created, entry{p, st})
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			cleanup()
			return nil, err
		}
		st, err := f.Stat()
		f.Close()
		if err != nil {
			cleanup()
			return nil, err
		}
		created = append(created, entry{path, st})
	}
	return cleanup, nil
}
