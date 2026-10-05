// native tiers of the process checks: the session capability set, deleted
// files still in use, temp-directory cwds, the proc-vs-ps comparison, and the
// cryptominer hunt.

package linux

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

	"karma/internal/model"
)

// nativeProcCaps mirrors sessionCapsScript: the host's own container markers
// decide the context line; a container session prints its whole capability set
// (the standing escape surface), a host session stops at the context line.
func nativeProcCaps(ctx context.Context) (string, error) {
	if !inContainer(ctx) {
		return "context: host\n", nil
	}
	var b strings.Builder
	b.WriteString("context: container\n")
	if haveBinary("capsh") {
		b.WriteString("== capsh --print\n")
		b.WriteString(runHost(ctx, []string{"capsh", "--print"}, false).out)
	} else {
		b.WriteString("== /proc/self/status\n")
		b.WriteString(capStatusLines())
	}
	return b.String(), nil
}

// inContainer reads the host's own container markers: /.dockerenv (Docker),
// /run/.containerenv (Podman), the PID 1 cgroup path, and systemd-detect-virt.
func inContainer(ctx context.Context) bool {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	if body, err := os.ReadFile("/proc/1/cgroup"); err == nil &&
		containerCgroupRe.Match(body) {
		return true
	}
	return runHost(ctx, []string{"systemd-detect-virt", "--container"}, false).ok
}

var containerCgroupRe = regexp.MustCompile(`(?i)(docker|containerd|kubepods|libpod|lxc|kata)[/.-]`)

// capStatusLines reads the Cap* masks from the session's own status.
func capStatusLines() string {
	body, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "Cap") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// nativeDeletedExe collapses the three script tiers into one ladder: lsof's
// +L1 listing when installed, otherwise the /proc link walk collecting the
// kernel's " (deleted)" target suffix — the shell walk's own rows.
func nativeDeletedExe(ctx context.Context) (string, error) {
	if haveBinary("lsof") {
		// A failing lsof with no output falls through to the /proc walk, the
		// way the script chain falls from the lsof tier to the walk tier.
		if res := runHost(ctx, []string{"lsof", "-wn", "+L1"}, false); res.ok || strings.TrimSpace(res.out) != "" {
			return res.out, nil
		}
	}
	// One /proc snapshot serves the three link passes, like the script's
	// single /proc/[0-9]* glob expansion covering them in order.
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
// deleted — the same mark lsof reports.
func printDeletedLink(b *strings.Builder, link string) {
	target, err := os.Readlink(link)
	if err != nil || !strings.HasSuffix(target, " (deleted)") {
		return
	}
	fmt.Fprintf(b, "%s -> %s\n", strings.TrimPrefix(link, "/proc/"), target)
}

// nativeCwdTmp mirrors cwdTmpScript: every process whose working directory
// sits inside a temp directory.
func nativeCwdTmp(ctx context.Context) (string, error) {
	var b strings.Builder
	for _, pid := range procPIDs() {
		if ctx.Err() != nil {
			return b.String(), ctx.Err()
		}
		target, err := os.Readlink(filepath.Join("/proc", pid, "cwd"))
		if err != nil {
			continue
		}
		for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
			if strings.HasPrefix(target, prefix) {
				fmt.Fprintf(&b, "/proc/%s -> %s\n", pid, target)
				break
			}
		}
	}
	return b.String(), nil
}

// nativeHiddenProcs mirrors hiddenProcsScript: the symmetric difference of the
// /proc listing and ps's own listing, numerically ordered, each survivor
// re-confirmed against /proc so a process that just exited drops out.
func nativeHiddenProcs(ctx context.Context) (string, error) {
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

// minerPsRe is the ps filter: the family alternation bounded with \b plus the
// stratum protocol marker, case-sensitive like the script's grep -E.
var minerPsRe = regexp.MustCompile(`\b(?:` + minerFamily + `)\b|\bstratum\+?(?:tcp|ssl):`)

// minerDropPaths is the fixed drop-path list the ls section reads.
var minerDropPaths = []string{
	"/tmp/.a", "/var/tmp/.a", "/dev/.a", "/dev/shm/.a",
	"/tmp/xmr", "/tmp/config.json", "/var/tmp/config.json", "/dev/shm/config.json",
	"/tmp/secure.sh", "/tmp/auth.sh", "/usr/.work/work64",
}

// minerNameGlobs is the temp-name walk's -iname list, lowercased: the match
// itself is case-insensitive.
var minerNameGlobs = []string{
	"*xmrig*", "*minerd*", "*cpuminer*", "kworkerds*", "kdevtmpfsi*",
	"kinsing*", "watchbog*", "sustes*", "sysupdate*", "sysguard*",
	"networkservice*", "config.json",
}

// minerPsLines filters snapshot rows through the miner pattern, dropping the
// script tier's "grep" noise.
func minerPsLines(entries []procEntry, boot, now time.Time, uptime float64, memTotal int64) []string {
	var out []string
	for _, e := range entries {
		if line := psAuxRow(e, boot, now, uptime, memTotal); minerPsRe.MatchString(line) && !strings.Contains(line, "grep") {
			out = append(out, line)
		}
	}
	return out
}

// nativeMiner mirrors minerScript: matched process lines, the fixed drop-path
// attributes, and the temp-name walk's ls -l batch. The ps scan reads the
// /proc snapshot (an interposed ps cannot hide a miner), and the ls -l rows
// come from lsBody in-process. The ps section drops lines carrying "grep"
// exactly like the script's second grep.
func nativeMiner(ctx context.Context) (string, error) {
	entries, boot, uptime, memTotal, ok := procSnapshot(ctx)
	if !ok {
		return "", model.ErrTierUnavailable
	}
	names := newNameCache()
	now := time.Now()
	var b strings.Builder
	b.WriteString("== ps\n")
	for _, line := range minerPsLines(entries, boot, now, uptime, memTotal) {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString("== drop paths\n")
	for _, path := range minerDropPaths {
		if info, err := os.Stat(path); err == nil {
			b.WriteString(lsBody(info, path, names))
			b.WriteByte('\n')
		}
	}
	b.WriteString("== temp names\n")
	var hits []string
	for _, dir := range tmpDirs {
		err := walkTree(ctx, dir, 4, true, nil, func(path string, info os.FileInfo) bool {
			if !info.Mode().IsRegular() {
				return true
			}
			name := strings.ToLower(filepath.Base(path))
			if matchAny(minerNameGlobs, name) {
				hits = append(hits, path)
			}
			return true
		})
		if err != nil {
			return b.String(), err
		}
	}
	for _, hit := range hits {
		if info, err := os.Stat(hit); err == nil {
			b.WriteString(lsBody(info, hit, names))
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}
