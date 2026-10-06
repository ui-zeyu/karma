// The top(1) snapshot tier: the banner, the task and memory summaries, and the
// process table in %CPU order. procps compares its first frame against a reading
// taken at startup, so its own first pass prints a near-zero delta however busy
// the host is; the summary here is the since-boot average instead.

package native

import (
	"context"
	"fmt"
	"strings"

	"karma/internal/model"
)

// Top renders a top -b snapshot: banner, task and memory summaries, and
// the process table in %CPU order.
func Top(ctx context.Context) (string, error) {
	snap := procSnapshot(ctx)
	if !snap.ok {
		return "", model.ErrTierUnavailable
	}
	entries := sortedByKey(snap.entries, func(e procEntry) float64 { return e.cpuPercent(snap.uptime) })
	var b strings.Builder
	fmt.Fprintf(&b, "top - %s\n", uptimeBannerBody())
	fmt.Fprintf(&b, "Tasks: %3d total, %3d running, %3d sleeping, %3d stopped, %3d zombie\n",
		len(entries), countState(entries, "R"), countState(entries, sleepStates),
		countState(entries, "Tt"), countState(entries, "Z"))
	b.WriteString(cpuSummaryLine())
	b.WriteString(memSummaryLine(snap.memTotal))
	b.WriteString("\n    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "%7d %-8s %3d %3d %7d %6d %6d %c %5.1f %5.1f %9s %s\n",
			e.pid, psUserCell(e.user), e.priority, e.nice,
			e.vsizeKiB(), e.rssKiB(), e.shrKiB(),
			e.state, e.cpuPercent(snap.uptime), e.memPercent(snap.memTotal),
			topTimeFormat(e.cpuSeconds()), e.args)
	}
	return b.String(), snap.cutReason(ctx)
}

// sleepStates is what procps folds into top's "sleeping" count: the
// interruptible sleep plus the states it tallies as "other" — idle kernel
// threads (I), parked (P) and dying (X). The plain S count alone drops every
// idle thread, which is about half of /proc on a stock kernel.
const sleepStates = "SIPX"

// countState counts processes whose run state is one of the given letters.
func countState(entries []procEntry, states string) int {
	n := 0
	for _, e := range entries {
		if strings.ContainsRune(states, rune(e.state)) {
			n++
		}
	}
	return n
}

// topTimeFormat is TIME+'s mm:ss.cc.
func topTimeFormat(secs float64) string {
	total := int(secs * 100)
	return fmt.Sprintf("%d:%02d.%02d", total/6000, (total/100)%60, total%100)
}

// cpuSummaryLine renders the %Cpu(s) line from /proc/stat's cumulative
// counters: since-boot average shares. top's own first frame is not that
// number — it compares against a reading taken at startup, so its first pass
// prints a near-zero delta (0.0 us … 100.0 id) however busy the host is.
func cpuSummaryLine() string {
	stat, err := procFS().Stat()
	if err != nil {
		return ""
	}
	c := stat.CPUTotal
	total := c.User + c.Nice + c.System + c.Idle + c.Iowait +
		c.IRQ + c.SoftIRQ + c.Steal + c.Guest + c.GuestNice
	if total <= 0 {
		return ""
	}
	pct := func(n float64) float64 { return n / total * 100 }
	return fmt.Sprintf("%%Cpu(s):  %4.1f us,  %4.1f sy,  %4.1f ni, %4.1f id,  %4.1f wa,  %4.1f hi,  %4.1f si,  %4.1f st\n",
		pct(c.User), pct(c.System), pct(c.Nice), pct(c.Idle), pct(c.Iowait), pct(c.IRQ), pct(c.SoftIRQ), pct(c.Steal))
}

// memSummaryLine renders the MiB Mem/Swap lines from /proc/meminfo. The Swap
// line carries the container-safe "avail Mem" figure (MemAvailable) that
// current procps prints at its end.
func memSummaryLine(memTotal int64) string {
	if memTotal <= 0 {
		return ""
	}
	mi, err := procFS().Meminfo()
	if err != nil {
		return ""
	}
	kib := func(p *uint64) int64 {
		if p == nil {
			return 0
		}
		return int64(*p) * 1024
	}
	cache := kib(mi.Buffers) + kib(mi.Cached) + kib(mi.SReclaimable)
	// procps derives "used" from MemAvailable (falling back to MemFree when a
	// kernel reports an impossible available figure), so used and buff/cache
	// overlap and the four numbers need not add up to the total
	used := memTotal - kib(mi.MemAvailable)
	if used < 0 {
		used = memTotal - kib(mi.MemFree)
	}
	mib := func(b int64) float64 { return float64(b) / 1048576 }
	return fmt.Sprintf("MiB Mem : %8.1f total, %8.1f free, %8.1f used, %8.1f buff/cache\n"+
		"MiB Swap: %8.1f total, %8.1f free, %8.1f used. %8.1f avail Mem\n",
		mib(memTotal), mib(kib(mi.MemFree)), mib(used), mib(cache),
		mib(kib(mi.SwapTotal)), mib(kib(mi.SwapFree)), mib(kib(mi.SwapTotal)-kib(mi.SwapFree)),
		mib(kib(mi.MemAvailable)))
}
