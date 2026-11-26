//go:build unix

package audit

import "syscall"

// pidAlive asks the kernel whether a pid exists. A permission error still
// proves existence: kill(0) only refuses the signal, not the question.
func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
