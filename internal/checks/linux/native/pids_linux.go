//go:build linux

package native

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"karma/internal/model"
)

// scanLimit caps the in-process tier's brute force. pid_max is 4M on
// 64-bit kernels; a kill(0) sweep costs well under a microsecond per miss,
// so 1M keeps the worst case around a second while covering every PID a real
// host plausibly holds.
const scanLimit = 1 << 20

// HiddenPIDs is the local-channel tier of the hidden-pids check: the
// brute force runs inside karma, so it is much faster than the shell tier and
// can afford a deeper scan cap. Requires /proc (present on every Linux); the
// wrong-platform case lives in pids_native_other.go.
func HiddenPIDs(ctx context.Context) (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	pidMax, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pidMax < 1 {
		return "", fmt.Errorf("pid_max: %q", string(raw))
	}
	scan := hiddenPidScan{
		pidMax:   pidMax,
		scanCap:  min(pidMax, scanLimit),
		euid:     syscall.Geteuid(),
		kill0:    func(pid int) bool { return syscall.Kill(pid, syscall.Signal(0)) == nil },
		fdExists: func(pid int) bool { _, err := os.Stat(fmt.Sprintf("/proc/%d/fd", pid)); return err == nil },
		listPIDs: listProcPIDs,
		readFile: func(path string) (string, bool) {
			b, err := os.ReadFile(path)
			if err != nil {
				return "", false
			}
			return string(b), true
		},
	}
	return scan.run(ctx)
}

// listProcPIDs is the readdir view: top-level PIDs plus every visible
// process's thread IDs. Non-leader threads never appear at /proc's top level,
// so the task walk is what keeps threads from reading as hidden.
func listProcPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		if n, ok := numeric(e.Name()); ok {
			pids = append(pids, n)
		}
	}
	var tids []int
	for _, pid := range pids {
		tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
		if err != nil {
			continue
		}
		for _, t := range tasks {
			if n, ok := numeric(t.Name()); ok {
				tids = append(tids, n)
			}
		}
	}
	return append(pids, tids...)
}

// numeric reports the value of an all-digits name.
func numeric(name string) (int, bool) {
	if name == "" {
		return 0, false
	}
	for _, c := range name {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(name)
	return n, err == nil
}
