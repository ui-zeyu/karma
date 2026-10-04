//go:build windows

// Windows process-tree stop: taskkill /T collects children too; on failure fall back to killing this process.
// An absolute path avoids depending on PATH.
package session

import (
	"os/exec"
	"strconv"
)

const taskkillPath = `C:\Windows\System32\taskkill.exe`

func prepareStop(cmd *exec.Cmd) func(pid int) {
	return func(pid int) {
		tree := exec.Command(taskkillPath, "/PID", strconv.Itoa(pid), "/T", "/F")
		_ = tree.Run()
	}
}
