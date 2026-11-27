package audit

// The hidden-pid sweep: the kernel is asked directly whether a pid exists, and the answer is compared with two /proc listings.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// pidMax reads the kernel's pid ceiling.
func pidMax() int {
	data, err := os.ReadFile(pidMaxPath)
	if err != nil {
		return 0
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || value < 2 {
		return 0
	}
	return value
}

// readHiddenPIDs asks the kernel directly whether a pid exists and compares
// the answer with two /proc listings. A pid absent from both listings while
// kill(0) sees it is hidden from getdents: the process's directory entry was
// scrubbed while the kernel still schedules it. ns_last_pid narrows the range
// when it is readable; pid_max is the fallback.

func readHiddenPIDs(ctx context.Context) ([]int, []Coverage) {
	if hidepid := procHidePIDs(); hidepid > 0 && os.Geteuid() != 0 {
		return nil, []Coverage{coverageGap("kernel", fmt.Sprintf("process space not scanned: /proc is mounted with hidepid=%d and this run is not root", hidepid))}
	}
	before, ok := procPIDs()
	if !ok {
		return nil, []Coverage{coverageAbsent("kernel", "process space unreadable: /proc could not be listed")}
	}
	limit := pidCeiling(before)
	if limit == 0 {
		return nil, []Coverage{coverageGap("kernel", "process space not scanned: "+pidMaxPath+" is unreadable")}
	}
	var gaps []Coverage
	hits := scanPIDs(ctx, limit, before)
	after, ok := procPIDs()
	if !ok {
		return nil, append(gaps, coverageGap("kernel", "process space unreadable after the scan: /proc could not be listed"))
	}
	var hidden []int
	for _, pid := range hits {
		if before[pid] || after[pid] || isThread(pid) || !pidAlive(pid) {
			continue
		}
		hidden = append(hidden, pid)
	}
	sort.Ints(hidden)
	var notes []Coverage
	hidden, notes = shownMore(hidden, hiddenPIDShown, "kernel", "hidden process(es)")
	gaps = append(gaps, notes...)
	return hidden, gaps
}

// pidCeiling is the highest pid the namespace may have allocated. ns_last_pid
// is the kernel's own last allocation; when it sits above every visible pid,
// the allocation sequence has not wrapped and a hidden process cannot sit
// above it. A wrapped sequence (ns_last_pid below the highest visible pid) is
// indistinguishable from a reset, so the ceiling is pid_max. The file is
// root-only on some hosts; pid_max is the fallback there too.

func pidCeiling(known map[int]bool) int {
	limit := pidMax()
	if limit == 0 {
		return 0
	}
	visible := 0
	for pid := range known {
		if pid > visible {
			visible = pid
		}
	}
	data, err := os.ReadFile("/proc/sys/kernel/ns_last_pid")
	if err != nil {
		return limit
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || value <= 0 || value >= limit {
		return limit
	}
	if value > visible {
		return value + 1
	}
	return limit
}

// procHidePIDs reads the /proc mount's hidepid option. Any non-zero value
// hides other accounts' processes from the directory listing, which would
// make an ordinary process look hidden.

func procHidePIDs() int {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[4] != "/proc" {
			continue
		}
		for _, option := range strings.Split(fields[5], ",") {
			value, ok := strings.CutPrefix(option, "hidepid=")
			if !ok {
				continue
			}
			hidepid, _ := strconv.Atoi(value)
			return hidepid
		}
	}
	return 0
}

// isThread reports whether pid is a non-leader thread. Threads answer kill(0)
// but have no top-level /proc directory entry; without this check every
// thread would read as a hidden process.

func isThread(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	tgid, self := 0, 0
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "Tgid:"); ok {
			tgid, _ = strconv.Atoi(strings.TrimSpace(value))
		}
		if value, ok := strings.CutPrefix(line, "Pid:"); ok {
			self, _ = strconv.Atoi(strings.TrimSpace(value))
		}
	}
	return tgid > 0 && self > 0 && tgid != self
}

// procPIDs lists the numeric entries of /proc.

func procPIDs() (map[int]bool, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	pids := make(map[int]bool, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err == nil {
			pids[pid] = true
		}
	}
	return pids, true
}

// scanPIDs asks kill(0) about every pid the kernel could have handed out. A
// hidden process still answers; a live one that started after the first
// listing is filtered by the second listing in readHiddenPIDs. The sweep is
// chunked across workers because a full sweep of a raised pid_max is millions
// of questions.

func scanPIDs(ctx context.Context, limit int, known map[int]bool) []int {
	hits := make([][]int, workerCount(8))
	each(ctx, limit, len(hits), func(w, i int) {
		if i < 2 || known[i] {
			return
		}
		if pidAlive(i) {
			hits[w] = append(hits[w], i)
		}
	})
	var out []int
	for _, chunk := range hits {
		out = append(out, chunk...)
	}
	return out
}

// collectLoader reads ld.so.conf, its includes and the directories they name.
// The configuration files are TCB objects; every search directory is checked
// for a non-root owner or group/other write, and every unowned .so inside one
// is a candidate for a soname replacement.
