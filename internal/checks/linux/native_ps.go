// native_ps: the process table straight from /proc, parsed by
// prometheus/procfs. ps, pstree, and the top snapshot all render the same
// in-process listing, so no userspace interposition (an LD_PRELOAD hook in a
// wrapped ps, a PATH shadow) can reshape the evidence on the local channel.
// The deliberate exception is the hidden-procs comparison, which keeps asking
// the host's own ps: divergence from this listing is the tamper signal.

package linux

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/procfs"

	"karma/internal/model"
)

// clkTck is USER_HZ, the unit /proc/[pid]/stat counts time in. Every Linux
// on any supported architecture runs at 100.
const clkTck = 100

// procEntry carries the fields the ps formats print, already resolved from
// /proc/[pid]/{stat,status,cmdline,statm}.
type procEntry struct {
	pid, ppid, pgrp, sid, tpgid int
	ttyNr                       int
	state                       byte
	comm, args, user            string
	utime, stime, starttime     int64 // clock ticks
	vsize                       int64 // bytes
	rss, shr                    int64 // pages
	priority, nice, numThreads  int
}

// procFS opens the one /proc reader: the process table, boot time, CPU and
// memory totals all come through it. Every accessor reports its own error, so
// a host without /proc (the macOS shell ladder) falls through to the script
// tier without a separate probe.
func procFS() procfs.FS {
	fs, _ := procfs.NewDefaultFS()
	return fs
}

// procSnapshot gathers every process in numeric pid order plus the machine
// facts (boot time, uptime, memory) the derived columns need. ok is false
// when /proc is absent, the script tier's "no ps" case.
func procSnapshot(ctx context.Context) (entries []procEntry, boot time.Time, uptime float64, memTotal int64, ok bool) {
	fs := procFS()
	stat, err := fs.Stat()
	if err != nil {
		return nil, time.Time{}, 0, 0, false
	}
	boot = time.Unix(int64(stat.BootTime), 0)
	uptime = readProcUptime()
	memTotal = readMemTotal()
	procs, err := fs.AllProcs()
	if err != nil {
		return nil, time.Time{}, 0, 0, false
	}
	names := newNameCache()
	for _, p := range procs {
		if ctx.Err() != nil {
			return entries, boot, uptime, memTotal, true
		}
		if e, good := readProcEntry(p, names); good {
			entries = append(entries, e)
		}
	}
	slices.SortFunc(entries, func(a, b procEntry) int { return a.pid - b.pid })
	return entries, boot, uptime, memTotal, true
}

// readProcEntry loads one process through procfs; a process that exited
// mid-walk drops out, like ps silently losing it. The euid is the second Uid
// field, matching ps's USER column.
func readProcEntry(p procfs.Proc, names *nameCache) (procEntry, bool) {
	st, err := p.Stat()
	if err != nil || st.State == "" {
		return procEntry{}, false
	}
	e := procEntry{
		pid: st.PID, ppid: st.PPID, pgrp: st.PGRP, sid: st.Session, tpgid: st.TPGID,
		ttyNr: st.TTY, state: st.State[0], comm: st.Comm,
		utime: int64(st.UTime), stime: int64(st.STime), starttime: int64(st.Starttime),
		vsize: int64(st.VSize), rss: int64(st.RSS),
		priority: st.Priority, nice: st.Nice, numThreads: st.NumThreads,
	}
	e.user = "?"
	if status, err := p.NewStatus(); err == nil {
		e.user = names.user(int(status.UIDs[1]))
	}
	if argv, err := p.CmdLine(); err == nil && len(argv) > 0 {
		e.args = strings.Join(argv, " ")
	} else if e.state == 'Z' {
		e.args = "[" + e.comm + "] <defunct>"
	} else {
		e.args = "[" + e.comm + "]"
	}
	if statm, err := p.Statm(); err == nil {
		e.shr = int64(statm.Shared)
	}
	return e, true
}

// bootTime is btime, the wall clock of pid 1's birth: the utmp BOOT_TIME
// record is matched against it. A host without /proc reports the zero time.
func bootTime() time.Time {
	stat, err := procFS().Stat()
	if err != nil || stat.BootTime == 0 {
		return time.Time{}
	}
	return time.Unix(int64(stat.BootTime), 0)
}

// readProcUptime returns the first field of /proc/uptime in seconds. procfs
// exposes no uptime accessor (only the boot wall clock), and the file is one
// number, so it is read directly.
func readProcUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	secs, _ := strconv.ParseFloat(fields[0], 64)
	return secs
}

// readMemTotal returns MemTotal in bytes, %MEM's denominator.
func readMemTotal() int64 {
	mi, err := procFS().Meminfo()
	if err != nil || mi.MemTotal == nil {
		return 0
	}
	return int64(*mi.MemTotal) * 1024
}

// ttyName decodes stat's tty_nr: devpts majors are pts/N, major 4 the console
// and serial ttys, 0 no controlling terminal (ps's "?").
func ttyName(nr int) string {
	if nr == 0 {
		return "?"
	}
	major := (nr >> 8) & 0xfff
	minor := nr & 0xff
	switch {
	case major >= 136 && major <= 143: // devpts
		return fmt.Sprintf("pts/%d", minor)
	case major == 4 && minor < 64:
		return fmt.Sprintf("tty%d", minor)
	case major == 4:
		return fmt.Sprintf("ttyS%d", minor-64)
	case major == 5 && minor == 0:
		return "tty"
	case major == 5 && minor == 1:
		return "console"
	case major == 1 && minor == 3:
		return "ptmx"
	default:
		return fmt.Sprintf("%d:%d", major, minor)
	}
}

// cpuPercent is ps's lifetime average: total ticks over elapsed lifetime.
func (e procEntry) cpuPercent(uptime float64) float64 {
	life := uptime - float64(e.starttime)/clkTck
	if life < 0.01 {
		life = 0.01
	}
	return float64(e.utime+e.stime) / clkTck / life * 100
}

// memPercent is resident memory over MemTotal.
func (e procEntry) memPercent(memTotal int64) float64 {
	if memTotal <= 0 {
		return 0
	}
	return float64(e.rss*int64(os.Getpagesize())) / float64(memTotal) * 100
}

// cpuSeconds is the accumulated CPU time in seconds (ps's TIME column).
func (e procEntry) cpuSeconds() float64 {
	return float64(e.utime+e.stime) / clkTck
}

// startClock renders ps's START column: wall clock within the last day, the
// date ("Oct05") before that.
func (e procEntry) startClock(boot time.Time, now time.Time) string {
	if boot.IsZero() {
		return "?"
	}
	start := boot.Add(time.Duration(e.starttime) * time.Second / clkTck)
	if start.After(now.Add(-24*time.Hour)) && !start.After(now) {
		return start.Format("15:04")
	}
	return start.Format("Jan02")
}

// psTimeFormat is TIME's mm:ss; minutes run past an hour (ps prints 188:20).
func psTimeFormat(secs float64) string {
	total := int(secs + 0.5)
	return fmt.Sprintf("%d:%02d", total/60, total%60)
}

// psStatString is the STAT column: state plus the modifiers ps shows (session
// leader, multithreaded, foreground).
func (e procEntry) psStatString() string {
	s := string(e.state)
	if e.sid != 0 && e.pid == e.sid {
		s += "s"
	}
	if e.numThreads > 1 {
		s += "l"
	}
	if e.ttyNr != 0 && e.tpgid == e.pgrp {
		s += "+"
	}
	return s
}

// psAuxHeader is the procps aux header the table styler anchors on.
const psAuxHeader = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"

// psAuxRow renders one auxww row: the shape every ps aux consumer (and the
// miner filter) matches on.
func psAuxRow(e procEntry, boot time.Time, now time.Time, uptime float64, memTotal int64) string {
	return fmt.Sprintf("%-8s %5d %4.1f %4.1f %6d %5d %-7s %-4s %-5s %6s %s",
		e.user, e.pid, e.cpuPercent(uptime), e.memPercent(memTotal),
		e.vsize/1024, e.rss*int64(os.Getpagesize())/1024,
		ttyName(e.ttyNr), e.psStatString(), e.startClock(boot, now),
		psTimeFormat(e.cpuSeconds()), e.args)
}

// psEfRow renders one `ps -ef` row.
func psEfRow(e procEntry, boot time.Time, now time.Time, uptime float64) string {
	c := int(e.cpuPercent(uptime) + 0.5)
	return fmt.Sprintf("%-8s %6d %6d %3d %-5s %-8s %6s %s",
		e.user, e.pid, e.ppid, c, e.startClock(boot, now),
		ttyName(e.ttyNr), psTimeFormat(e.cpuSeconds()), e.args)
}

// nativePsAux renders the auxww table (pid order; forest nesting is pstree's
// job on this tier).
func nativePsAux(ctx context.Context) (string, error) {
	entries, boot, uptime, memTotal, ok := procSnapshot(ctx)
	if !ok {
		return "", model.ErrTierUnavailable
	}
	now := time.Now()
	var b strings.Builder
	b.WriteString(psAuxHeader + "\n")
	for _, e := range entries {
		b.WriteString(psAuxRow(e, boot, now, uptime, memTotal))
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// nativePsEf renders the System V table.
func nativePsEf(ctx context.Context) (string, error) {
	entries, boot, uptime, _, ok := procSnapshot(ctx)
	if !ok {
		return "", model.ErrTierUnavailable
	}
	now := time.Now()
	var b strings.Builder
	b.WriteString("UID          PID  PPID  C STIME TTY          TIME CMD\n")
	for _, e := range entries {
		b.WriteString(psEfRow(e, boot, now, uptime))
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// nativePsSort renders an aux table sorted by a column, ps --sort's shape;
// the machine facts arrive once so the comparator does no file I/O.
func nativePsSort(ctx context.Context,
	by func(a, b procEntry, uptime float64, memTotal int64) int) (string, error) {
	entries, boot, uptime, memTotal, ok := procSnapshot(ctx)
	if !ok {
		return "", model.ErrTierUnavailable
	}
	slices.SortStableFunc(entries, func(a, b procEntry) int { return by(a, b, uptime, memTotal) })
	now := time.Now()
	var b strings.Builder
	b.WriteString(psAuxHeader + "\n")
	for _, e := range entries {
		b.WriteString(psAuxRow(e, boot, now, uptime, memTotal))
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// nativePsCPU is `ps aux --sort=-%cpu`.
func nativePsCPU(ctx context.Context) (string, error) {
	return nativePsSort(ctx, func(a, b procEntry, uptime float64, _ int64) int {
		return cmpFloatDesc(b.cpuPercent(uptime), a.cpuPercent(uptime))
	})
}

// nativePsMem is `ps aux --sort=-%mem`.
func nativePsMem(ctx context.Context) (string, error) {
	return nativePsSort(ctx, func(a, b procEntry, _ float64, _ int64) int {
		return cmpInt64Desc(b.rss, a.rss)
	})
}

// cmpFloatDesc/cmpInt64Desc report how the first argument should sort
// relative to the second (positive means first after second).
func cmpFloatDesc(a, b float64) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	}
	return 0
}

func cmpInt64Desc(a, b int64) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	}
	return 0
}

// nativeTop renders a top -b snapshot: banner, task and memory summaries, and
// the process table in %CPU order.
func nativeTop(ctx context.Context) (string, error) {
	entries, _, uptime, memTotal, ok := procSnapshot(ctx)
	if !ok {
		return "", model.ErrTierUnavailable
	}
	slices.SortStableFunc(entries, func(a, b procEntry) int {
		return cmpFloatDesc(b.cpuPercent(uptime), a.cpuPercent(uptime))
	})
	var b strings.Builder
	fmt.Fprintf(&b, "top - %s\n", uptimeBannerLine())
	fmt.Fprintf(&b, "Tasks: %d total, %d running, %d sleeping, %d stopped, %d zombie\n",
		len(entries), countState(entries, 'R'), countState(entries, 'S'),
		countState(entries, 'T'), countState(entries, 'Z'))
	b.WriteString(cpuSummaryLine())
	b.WriteString(memSummaryLine(memTotal))
	b.WriteString("\n  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "%6d %-8s %3d %3d %7d %6d %6d %c %5.1f %5.1f %9s %s\n",
			e.pid, e.user, e.priority, e.nice,
			e.vsize/1024, e.rss*int64(os.Getpagesize())/1024, e.shr*int64(os.Getpagesize())/1024,
			e.state, e.cpuPercent(uptime), e.memPercent(memTotal),
			topTimeFormat(e.cpuSeconds()), e.args)
	}
	return b.String(), nil
}

// countState counts processes in one run state.
func countState(entries []procEntry, state byte) int {
	n := 0
	for _, e := range entries {
		if e.state == state {
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
// counters — since-boot shares, which is also what top's first pass shows.
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

// memSummaryLine renders the MiB Mem/Swap lines from /proc/meminfo.
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
	used := memTotal - kib(mi.MemFree) - cache
	mib := func(b int64) float64 { return float64(b) / 1048576 }
	return fmt.Sprintf("MiB Mem : %8.1f total, %8.1f free, %8.1f used, %8.1f buff/cache\nMiB Swap: %8.1f total, %8.1f free, %8.1f used.\n",
		mib(memTotal), mib(kib(mi.MemFree)), mib(used), mib(cache),
		mib(kib(mi.SwapTotal)), mib(kib(mi.SwapFree)), mib(kib(mi.SwapTotal)-kib(mi.SwapFree)))
}

// nativePstree renders the process tree from ppid links, pstree -ap's
// evidence in ASCII connectors.
func nativePstree(ctx context.Context) (string, error) {
	entries, _, _, _, ok := procSnapshot(ctx)
	if !ok {
		return "", model.ErrTierUnavailable
	}
	return renderPstree(entries), nil
}

// renderPstree prints the forest: every process whose parent is absent (pid
// 1, kernel threads) starts a root; children follow under ASCII connectors,
// args appended when the process has a command line.
func renderPstree(entries []procEntry) string {
	children := map[int][]procEntry{}
	byPid := map[int]bool{}
	for _, e := range entries {
		byPid[e.pid] = true
		children[e.ppid] = append(children[e.ppid], e)
	}
	var roots []procEntry
	for _, e := range entries {
		if !byPid[e.ppid] { // pid 1 and any orphan of a vanished parent
			roots = append(roots, e)
		}
	}
	var b strings.Builder
	var walk func(e procEntry, prefix, connector string, last bool)
	walk = func(e procEntry, prefix, connector string, last bool) {
		b.WriteString(prefix)
		b.WriteString(connector)
		fmt.Fprintf(&b, "%s(%d)", e.comm, e.pid)
		if e.args != "" && !strings.HasPrefix(e.args, "[") {
			b.WriteString(" " + e.args)
		}
		b.WriteByte('\n')
		kidPrefix := prefix
		if connector != "" {
			if last {
				kidPrefix += "  "
			} else {
				kidPrefix += "| "
			}
		}
		for i, kid := range children[e.pid] {
			kidLast := i == len(children[e.pid])-1
			conn := "|-"
			if kidLast {
				conn = "`-"
			}
			walk(kid, kidPrefix, conn, kidLast)
		}
	}
	lastRoot := len(roots) - 1
	for i, root := range roots {
		walk(root, "", "", i == lastRoot)
	}
	return b.String()
}
