// native tiers of the process checks: the session capability set, deleted
// files still in use, temp-directory cwds, the proc-vs-ps comparison, and the
// cryptominer hunt.

package native

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"karma/internal/localfs"
	"karma/internal/model"
	"karma/internal/script"
	"karma/internal/section"
)

// ProcCaps reads the session's capability set; the host's own container markers
// decide the context line. A container session prints its whole set
// (the standing escape surface), a host session stops at the context line.
// cgroupMarkers is the check's container-scope pattern, the same string its
// script greps for.
func ProcCaps(cgroupMarkers *regexp.Regexp) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if !inContainer(ctx, cgroupMarkers) {
			return "context: host\n", nil
		}
		var b strings.Builder
		b.WriteString("context: container\n")
		if haveBinary("capsh") {
			b.WriteString(section.Line("capsh --print"))
			b.WriteString(runHost(ctx, []string{"capsh", "--print"}, false).out)
		} else {
			b.WriteString(section.Line("/proc/self/status"))
			b.WriteString(capStatusLines())
		}
		return b.String(), nil
	}
}

// inContainer reads the host's own container markers: /.dockerenv (Docker),
// /run/.containerenv (Podman), the PID 1 cgroup path, and systemd-detect-virt.
// The cgroup pattern comes from the check, which is also what grades the
// markers this reports.
func inContainer(ctx context.Context, cgroupMarkers *regexp.Regexp) bool {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	if body, err := os.ReadFile("/proc/1/cgroup"); err == nil &&
		cgroupMarkers.Match(body) {
		return true
	}
	return runHost(ctx, []string{"systemd-detect-virt", "--container"}, false).ok
}

// capStatusLines reads the Cap* masks from the session's own status.
func capStatusLines() string {
	body, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ""
	}
	return filteredLines(string(body), func(line string) bool { return strings.HasPrefix(line, "Cap") })
}

// DeletedExe is one ladder: lsof's +L1 listing when installed, otherwise the
// /proc link walk collecting the kernel's " (deleted)" target suffix.
func DeletedExe(ctx context.Context) (string, error) {
	if haveBinary("lsof") {
		// A failing lsof with no output falls through to the /proc walk.
		if res := runHost(ctx, []string{"lsof", "-wn", "+L1"}, false); res.ok || strings.TrimSpace(res.out) != "" {
			return res.out, nil
		}
	}
	// One /proc snapshot serves the three link passes: exe, cwd, then the fd
	// directories, in that order.
	pids := procPIDs()
	var b strings.Builder
	for _, kind := range []string{"exe", "cwd"} {
		for _, pid := range pids {
			if ctx.Err() != nil {
				return b.String(), ctx.Err()
			}
			printDeletedLink(&b, filepath.Join("/proc", pid, kind))
		}
	}
	for _, pid := range pids {
		if ctx.Err() != nil {
			return b.String(), ctx.Err()
		}
		fds, err := os.ReadDir(filepath.Join("/proc", pid, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			printDeletedLink(&b, filepath.Join("/proc", pid, "fd", fd.Name()))
		}
	}
	return b.String(), nil
}

// printDeletedLink appends one row when the kernel marked the link target
// deleted — the same mark lsof reports, in the shape the other two tiers print.
func printDeletedLink(b *strings.Builder, link string) {
	target, err := os.Readlink(link)
	if err != nil || !strings.HasSuffix(target, " (deleted)") {
		return
	}
	b.WriteString(script.DeletedLinkRow(link, target))
	b.WriteByte('\n')
}

// CwdTmp lists every process whose working directory sits inside one of the temp
// directories the check hands in.
func CwdTmp(tmpDirs []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		for _, pid := range procPIDs() {
			if ctx.Err() != nil {
				return b.String(), ctx.Err()
			}
			target, err := os.Readlink(filepath.Join("/proc", pid, "cwd"))
			if err != nil {
				continue
			}
			for _, dir := range tmpDirs {
				if strings.HasPrefix(target, dir+"/") {
					fmt.Fprintf(&b, "/proc/%s -> %s\n", pid, target)
					break
				}
			}
		}
		return b.String(), nil
	}
}

// HiddenProcs reports the symmetric difference of the /proc listing and ps's own
// listing, numerically ordered, each survivor
// re-confirmed against /proc so a process that just exited drops out.
func HiddenProcs(ctx context.Context) (string, error) {
	if !haveBinary("ps") {
		return "", model.ErrTierUnavailable
	}
	counts := map[string]int{}
	procList := procPIDs()
	for _, pid := range procList {
		counts[pid]++
	}
	for _, line := range strings.Split(runHost(ctx, []string{"ps", "-eo", "pid="}, false).out, "\n") {
		if pid := strings.TrimSpace(line); pid != "" {
			if _, err := strconv.Atoi(pid); err == nil {
				counts[pid]++
			}
		}
	}
	var differing []string
	for pid, count := range counts {
		if count == 1 {
			differing = append(differing, pid)
		}
	}
	slices.SortFunc(differing, func(a, b string) int {
		na, _ := strconv.Atoi(a)
		nb, _ := strconv.Atoi(b)
		return na - nb
	})
	var b strings.Builder
	for _, pid := range differing {
		if info, err := os.Stat(filepath.Join("/proc", pid)); err == nil && info.IsDir() {
			b.WriteString(pid)
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

// MinerScan is the cryptominer hunt's shape: the process-line pattern, the fixed
// drop paths whose attributes it prints, the temp-directory name globs, the
// directories the name walk covers, and the walk's depth cap. The check hands all
// five in, so the hunt and the rules that grade its rows cannot cover different
// names.
type MinerScan struct {
	Pattern   *regexp.Regexp
	DropPaths []string
	NameGlobs []string
	TempDirs  []string
	MaxDepth  int
}

// minerPsLines filters the aux rows through the hunt's pattern, dropping the
// lines that are the search's own "grep" noise. The rows are the forest ones, so
// this section reads the same however the table was read.
func minerPsLines(snap processSnapshot, now time.Time, pattern *regexp.Regexp) []string {
	var out []string
	for _, line := range psAuxForest(snap, now) {
		if pattern.MatchString(line) && !strings.Contains(line, "grep") {
			out = append(out, line)
		}
	}
	return out
}

// Miner hunts in place: matched process lines, the fixed drop-path attributes,
// and the temp-name walk's ls -l batch. The ps scan reads
// the /proc snapshot (an interposed ps cannot hide a miner), and the ls -l rows
// come from lsBody in-process. The ps section drops the lines that carry "grep"
// (the search's own noise), and the name walk crosses devices on purpose — a
// service's PrivateTmp mounts a tmpfs inside /tmp.
func Miner(scan MinerScan) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		snap := procSnapshot(ctx)
		if !snap.ok {
			return "", model.ErrTierUnavailable
		}
		names := localfs.NewNameCache()
		now := time.Now()
		var b strings.Builder
		b.WriteString(section.Line("ps"))
		for _, line := range minerPsLines(snap, now, scan.Pattern) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
		b.WriteString(section.Line("drop paths"))
		// The rows are sorted the way `LC_ALL=C ls -l` sorts its arguments, so a
		// batch reads in a stable order.
		var present []string
		for _, path := range scan.DropPaths {
			if _, err := os.Stat(path); err == nil {
				present = append(present, path)
			}
		}
		for _, path := range script.LsSorted(present) {
			if info, err := os.Stat(path); err == nil {
				b.WriteString(localfs.LsBody(info, path, names))
				b.WriteByte('\n')
			}
		}
		b.WriteString(section.Line("temp names"))
		var hits []string
		for _, dir := range scan.TempDirs {
			err := localfs.WalkTree(ctx, dir, scan.MaxDepth, false, nil, func(path string, info os.FileInfo) bool {
				if !info.Mode().IsRegular() {
					return true
				}
				name := strings.ToLower(filepath.Base(path))
				if localfs.MatchAny(scan.NameGlobs, name) {
					hits = append(hits, path)
				}
				return true
			})
			if err != nil {
				return b.String(), err
			}
		}
		for _, hit := range script.LsSorted(hits) {
			if info, err := os.Stat(hit); err == nil {
				b.WriteString(localfs.LsBody(info, hit, names))
				b.WriteByte('\n')
			}
		}
		return b.String(), snap.cutReason(ctx)
	}
}

// hiddenPidScan is the brute-force comparison with every oracle injected, so
// the algorithm is testable without touching the live /proc.
type hiddenPidScan struct {
	pidMax   int
	scanCap  int
	euid     int
	kill0    func(pid int) bool               // kernel-side existence oracle
	fdExists func(pid int) bool               // /proc/PID/fd lookup oracle (evidence)
	listPIDs func() []int                     // readdir view: PIDs and thread IDs
	readFile func(path string) (string, bool) // best-effort /proc reads for the report
}

func (s hiddenPidScan) run(ctx context.Context) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "scan: pid_max=%d scanned=1-%d oracle=kill(pid,0) vs /proc readdir (threads included)\n",
		s.pidMax, s.scanCap)
	if s.euid != 0 {
		b.WriteString("note: not running as root: readdir may hide other users' processes\n")
	}
	normal := map[int]bool{}
	for _, p := range s.listPIDs() {
		normal[p] = true
	}
	var candidates []int
	for pid := 1; pid <= s.scanCap; pid++ {
		// ctx.Err() is one atomic load; checking every iteration keeps
		// cancellation honest even for small caps
		if ctx.Err() != nil {
			return b.String(), ctx.Err()
		}
		if !normal[pid] && s.kill0(pid) {
			candidates = append(candidates, pid)
		}
	}
	if len(candidates) == 0 {
		return b.String(), nil
	}
	// Confirmation pass kills both races: a process that exited fails the
	// oracle again, and a process created between the two listings shows up
	// in the fresh readdir view.
	fresh := map[int]bool{}
	for _, p := range s.listPIDs() {
		fresh[p] = true
	}
	var hidden []int
	for _, pid := range candidates {
		if !fresh[pid] && s.kill0(pid) {
			hidden = append(hidden, pid)
		}
	}
	if len(hidden) == 0 {
		return b.String(), nil
	}
	b.WriteString(section.Line("hidden"))
	for _, pid := range hidden {
		fd := "no"
		if s.fdExists(pid) {
			fd = "yes"
		}
		comm, _ := s.readFile(fmt.Sprintf("/proc/%d/comm", pid))
		cmd, _ := s.readFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		fmt.Fprintf(&b, "PID %d  fd=%s  comm=%s  cmd='%s'\n", pid, fd,
			strings.TrimSpace(comm), strings.TrimRight(strings.ReplaceAll(cmd, "\x00", " "), " "))
	}
	return b.String(), nil
}
