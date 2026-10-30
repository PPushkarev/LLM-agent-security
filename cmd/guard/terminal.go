package main

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"guard/internal/guardrails"
)

// A pipe-based output cap would make interactive harnesses lose their terminal.
// Use a PTY for a terminal session; all output still passes the same byte budget.
func startHarness(cmd *exec.Cmd, stdin io.Reader, session *guardrails.Session, beforeStart func(string) error) (func(), error) {
	if stdin != os.Stdin || !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		cmd.Stdin = stdin
		cmd.Stdout = session.Output(os.Stdout)
		cmd.Stderr = session.Output(os.Stderr)
		return func() {}, cmd.Start()
	}
	return startTerminalHarness(cmd, os.Stdin, os.Stdout, session, beforeStart)
}
func startTerminalHarness(cmd *exec.Cmd, input, output *os.File, session *guardrails.Session, beforeStart func(string) error) (func(), error) {
	size, err := pty.GetsizeFull(input)
	if err != nil {
		return nil, err
	}
	master, slave, err := pty.Open()
	if err != nil {
		return nil, err
	}
	if err := pty.Setsize(master, size); err != nil {
		master.Close()
		slave.Close()
		return nil, err
	}
	if beforeStart != nil {
		if err := beforeStart(slave.Name()); err != nil {
			master.Close()
			slave.Close()
			return nil, err
		}
	}
	cmd.SysProcAttr.Setpgid = false
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	if err := cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		return nil, err
	}
	slave.Close()

	// Register a nonblocking PTY descriptor with Go's poller so reads wait for
	// readiness and Close can interrupt them. The original File was opened blocking.
	fd := int(master.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		master.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return nil, err
	}
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		master.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return nil, err
	}
	master.Close()
	master = os.NewFile(uintptr(duplicate), "guard-pty")

	state, err := term.MakeRaw(int(input.Fd()))
	if err != nil {
		master.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return nil, err
	}
	done := make(chan struct{})
	copied := make(chan struct{})
	resize := make(chan os.Signal, 1)
	signal.Notify(resize, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-resize:
				_ = pty.InheritSize(input, master)
			case <-done:
				return
			}
		}
	}()
	inputFD := int(input.Fd())
	go func() {
		buffer := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
			}
			fds := []unix.PollFd{{Fd: int32(inputFD), Events: unix.POLLIN}}
			ready, err := unix.Poll(fds, 100)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return
			}
			if ready == 0 {
				continue
			}
			select {
			case <-done:
				return
			default:
			}
			n, err := unix.Read(inputFD, buffer)
			if err != nil || n == 0 {
				return
			}
			if _, err := master.Write(buffer[:n]); err != nil {
				return
			}
		}
	}()
	go func() { _, _ = io.Copy(session.Output(output), master); close(copied) }()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			signal.Stop(resize)
			close(done)
			// Drain normal output before observing the final guardrail result. Bound the
			// wait if an orphan keeps the slave open after the main process has exited.
			select {
			case <-copied:
			case <-time.After(2 * time.Second):
			}
			master.Close()
			_ = term.Restore(int(input.Fd()), state)
		})
	}
	return cleanup, nil
}
