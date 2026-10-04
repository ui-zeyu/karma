//go:build unix

// POSIX process-tree stop: Setpgid creates an independent process group; on timeout SIGKILL the whole group.
// Windows branch: see stop_windows.go.

package session

import (
	"os/exec"
	"syscall"
)

func prepareStop(cmd *exec.Cmd) func(pid int) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return func(pid int) {
		// Ignore if the group has already exited
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}
