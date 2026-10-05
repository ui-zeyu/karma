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

// HiddenPIDs is the local-channel tier of the hidden-pids check: the
// brute force runs inside karma, so it sweeps the whole pid space where the
// shell tier must cap its interpreted loop. Requires /proc (present on every
// Linux); the wrong-platform case lives in pids_other.go.
func HiddenPIDs(ctx context.Context) (string, error) {
	scan, err := newHiddenPidScan()
	if err != nil {
		return "", err
	}
	return scan.run(ctx)
}

// newHiddenPidScan reads pid_max and wires every oracle to the live /proc.
// The scan cap is pid_max itself: it is the kernel's own bound on allocated
// PIDs, and a kill(0) probe costs ~0.6µs, so the 4M default sweeps in a
// couple of seconds even on a small box — nothing alive can sit above it.
func newHiddenPidScan() (hiddenPidScan, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return hiddenPidScan{}, model.ErrTierUnavailable
	}
	pidMax, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pidMax < 1 {
		return hiddenPidScan{}, fmt.Errorf("pid_max: %q", string(raw))
	}
	return hiddenPidScan{
		pidMax:   pidMax,
		scanCap:  pidMax,
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
	}, nil
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
