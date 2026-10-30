//go:build linux

package sandbox

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

// Restrict all Go runtime threads before starting any untrusted code. Inherited
// socketpair transport keeps working; creating host/abstract Unix sockets does
// not. Reject alternate syscall ABIs and io_uring syscall-filter bypasses.
func installLinuxSeccomp() error {
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	}
	deny := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	f := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	}
	if runtime.GOARCH == "amd64" {
		f = append(f, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x40000000, Jf: 1}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: deny})
	}
	for _, nr := range []uint32{unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PIDFD_GETFD, unix.SYS_SETNS, unix.SYS_UNSHARE, unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER, unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_MOVE_MOUNT, unix.SYS_OPEN_TREE, unix.SYS_MOUNT_SETATTR} {
		f = append(f, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: nr, Jf: 1}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: deny})
	}
	// socket(domain,...): only IP families, confined to our private net namespace.
	f = append(f,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_SOCKET, Jf: 4},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.AF_INET, Jt: 3},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.AF_INET6, Jt: 2},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: deny},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(f)
	if errno != 0 {
		return errno
	}
	if result != 0 {
		return fmt.Errorf("seccomp thread synchronization failed: %d", result)
	}
	return nil
}

const linuxExecHelper = "__guard_linux_exec_allow"

func runExecAllow(cmd *exec.Cmd, allow []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	b, _ := json.Marshal(allow)
	child := exec.Command(exe, append([]string{linuxExecHelper, base64.RawStdEncoding.EncodeToString(b), cmd.Path}, cmd.Args[1:]...)...)
	child.Env = cmd.Env
	child.Stdin = cmd.Stdin
	child.Stdout = cmd.Stdout
	child.Stderr = cmd.Stderr
	return child.Run()
}
func init() {
	if len(os.Args) < 2 || os.Args[1] != linuxExecHelper {
		return
	}
	runtime.LockOSThread()
	err := func() error {
		if len(os.Args) < 4 {
			return fmt.Errorf("invalid exec allow helper")
		}
		b, err := base64.RawStdEncoding.DecodeString(os.Args[2])
		if err != nil {
			return err
		}
		var allow []string
		if err = json.Unmarshal(b, &allow); err != nil {
			return err
		}
		// Require Landlock when execution allowlisting is requested; never ignore it.
		attr := struct{ Access uint64 }{unix.LANDLOCK_ACCESS_FS_EXECUTE}
		fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
		if errno != 0 {
			return fmt.Errorf("exec.allow requires Landlock: %w", errno)
		}
		defer unix.Close(int(fd))
		for _, path := range allow {
			p, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			// landlock_path_beneath_attr is packed (12 bytes).
			rule := struct {
				Access  uint64
				Parent  int32
				Padding uint32
			}{Access: unix.LANDLOCK_ACCESS_FS_EXECUTE, Parent: int32(p)}
			_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
			unix.Close(p)
			if errno != 0 {
				return errno
			}
		}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return err
		}
		_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0)
		if errno != 0 {
			return errno
		}
		return syscall.Exec(os.Args[3], os.Args[3:], os.Environ())
	}()
	fmt.Fprintln(os.Stderr, "guard Linux exec allowlist:", err)
	os.Exit(1)
}
