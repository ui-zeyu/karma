// native_ps: the process table straight from /proc, parsed by
// prometheus/procfs. ps, pstree, and the top snapshot all render the same
// in-process listing, so no userspace interposition (an LD_PRELOAD hook in a
// wrapped ps, a PATH shadow) can reshape the evidence on the local channel.
// The deliberate exception is the hidden-procs comparison, which keeps asking
// the host's own ps: divergence from this listing is the tamper signal.

package native

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/procfs"

	"karma/internal/localfs"
	"karma/internal/model"
	"karma/internal/runstate"
)

// clkTck is USER_HZ, the unit /proc/[pid]/stat counts time in. Every Linux
// on any supported architecture runs at 100.
const clkTck = 100

// procEntry carries the fields the ps formats print, already resolved from
// /proc/[pid]/{stat,status,cmdline,statm}.
type procEntry struct {
	pid, ppid, pgrp, sid, tpgid int
	tgid                        int
	ttyNr                       int
	state                       byte
	comm, args, user            string
	utime, stime, starttime     int64  // clock ticks
	vsize                       int64  // bytes
	rss, shr                    int64  // pages
	lockKiB                     uint64 // VmLck: pages locked into memory
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

// processSnapshot is one view of the process table: the entries in numeric pid
// order plus the machine facts the derived columns need. It is read-only once
// taken; a caller that reorders the entries copies them first.
type processSnapshot struct {
	entries  []procEntry
	boot     time.Time
	uptime   float64
	memTotal int64
	// ok is false when /proc is absent, the script tier's "no ps" case.
	ok bool
	// complete is false when the walk ended on cancellation instead of on the
	// end of /proc.
	complete bool
}

// procSnapshotKey is the run store's slot for that view (see runstate).
type procSnapshotKey struct{}

// procSnapshot returns the run's view of the process table, computed at the
// first request and shared from then on: one entry costs four /proc reads
// (stat, status, cmdline, statm), and ps, top, miner, and w all want the whole
// table while their checks run together. Outside a run — a unit test calling a
// body directly — each caller computes its own.
func procSnapshot(ctx context.Context) processSnapshot {
	store := runstate.From(ctx)
	if store == nil {
		return scanProcesses(ctx)
	}
	snap := runstate.Memo(store, procSnapshotKey{}, func() processSnapshot {
		return scanProcesses(ctx)
	})
	if !snap.complete && ctx.Err() == nil {
		// Another check's deadline cut the shared walk while this one still
		// has time: read our own rather than inherit the fragment.
		return scanProcesses(ctx)
	}
	return snap
}

// cutReason is the cancellation that stopped the walk before the end of /proc.
// A tier whose table is partial reports it, so the panel reads as a timeout (or
// an interrupt) with the rows already read, instead of passing the fragment off
// as the whole table. A complete walk, and a host without /proc, are nil.
func (s processSnapshot) cutReason(ctx context.Context) error {
	if s.complete {
		return nil
	}
	return ctx.Err()
}

// scanProcesses gathers every process once. A cancelled context ends the walk
// early and keeps the entries already read.
func scanProcesses(ctx context.Context) processSnapshot {
	fs := procFS()
	stat, err := fs.Stat()
	if err != nil {
		return processSnapshot{complete: true}
	}
	snap := processSnapshot{
		boot:     time.Unix(int64(stat.BootTime), 0),
		uptime:   readProcUptime(),
		memTotal: readMemTotal(),
	}
	procs, err := fs.AllProcs()
	if err != nil {
		return processSnapshot{complete: true}
	}
	names := localfs.NewNameCache()
	for _, p := range procs {
		if ctx.Err() != nil {
			// The entries read before the deadline are still this caller's
			// answer; complete stays false, so the shared slot never hands
			// the fragment to the checks that did not time out.
			break
		}
		if e, good := readProcEntry(p, names); good {
			snap.entries = append(snap.entries, e)
		}
	}
	slices.SortFunc(snap.entries, func(a, b procEntry) int { return cmp.Compare(a.pid, b.pid) })
	snap.ok = true
	snap.complete = ctx.Err() == nil
	return snap
}

// readProcEntry loads one process through procfs; a process that exited
// mid-walk drops out, like ps silently losing it. The euid is the second Uid
// field, matching ps's USER column; status also carries the thread group id
// (the STAT session-leader test) and VmLck (the locked-pages flag).
func readProcEntry(p procfs.Proc, names *localfs.NameCache) (procEntry, bool) {
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
	e.tgid = e.pid
	if status, err := p.NewStatus(); err == nil {
		e.user = names.User(int(status.UIDs[1]))
		e.tgid = status.TGID
		e.lockKiB = status.VmLck
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

// memPercent is resident memory over MemTotal, truncated to tenths the way
// procps does it: rss_bytes * 1000 / MemTotal_bytes with integer division,
// capped at 99.9 (a value that would print 100.0 never appears). The float
// form this replaced disagreed with ps in the last digit. A process at or over
// the total, and a hostile stat line, leave before the multiply.
func (e procEntry) memPercent(memTotal int64) float64 {
	if memTotal <= 0 {
		return 0
	}
	if e.rss <= 0 {
		return 0
	}
	rssBytes := e.rss * int64(os.Getpagesize())
	if rssBytes >= memTotal {
		return 99.9
	}
	return float64(rssBytes*1000/memTotal) / 10
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

// psStatString is the STAT column: state plus the modifiers ps shows, in
// procps' order — high priority (<), low priority (N), locked pages (L),
// session leader (s), multithreaded (l), foreground process group (+).
func (e procEntry) psStatString() string {
	s := string(e.state)
	if e.nice < 0 {
		s += "<"
	}
	if e.nice > 0 {
		s += "N"
	}
	if e.lockKiB > 0 {
		s += "L"
	}
	if e.tgid != 0 && e.tgid == e.sid {
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

// psUserCell is ps's USER/UID cell: an account name longer than the eight-cell
// column keeps seven characters and marks the cut with '+', so two rows never
// collide on a long service account.
func psUserCell(name string) string {
	if len(name) > 8 {
		return name[:7] + "+"
	}
	return name
}

// psAuxHeader is the procps aux header the table styler anchors on.
const psAuxHeader = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"

// forestRow is one row of the aux table in ps's forest order: the process, and
// the ladder ps draws at the head of its COMMAND cell.
type forestRow struct {
	entry  procEntry
	prefix string // four columns per level below the root; empty at the root
}

// forestRows orders the table the way ps does when the f flag is given, and
// works out each row's ladder.
//
// procps sorts its array by parent and then by start time, which is what puts a
// parent's children side by side; it then walks that array backwards and prints
// a tree for every process whose parent is not in the table, each tree depth
// first with its children in array order. A child of pid 1 prints at its
// parent's level — procps adopts init's children — which is what keeps a
// session chain from marching one column right for every sshd hop.
func forestRows(entries []procEntry) []forestRow {
	ordered := slices.Clone(entries)
	slices.SortStableFunc(ordered, func(a, b procEntry) int {
		// start time, then pid: processes born in the same tick stay in a
		// fixed order rather than the readdir order they arrived in
		return cmp.Or(
			cmp.Compare(a.ppid, b.ppid),
			cmp.Compare(a.starttime, b.starttime),
			cmp.Compare(a.pid, b.pid),
		)
	})
	children := make(map[int][]int, len(ordered))
	inTable := make(map[int]bool, len(ordered))
	for index, entry := range ordered {
		inTable[entry.pid] = true
		children[entry.ppid] = append(children[entry.ppid], index)
	}
	var (
		rows    []forestRow
		printed = make([]bool, len(ordered))
	)
	var walk func(index int, prefix string, hasSibling bool)
	walk = func(index int, prefix string, hasSibling bool) {
		entry := ordered[index]
		printed[index] = true
		rows = append(rows, forestRow{entry: entry, prefix: prefix})
		kids := children[entry.pid]
		for n, kid := range kids {
			if printed[kid] {
				continue
			}
			// Whether this row still has a sibling below it decides the bar
			// its children hang from; the child's own place decides only its
			// connector, which reads the same either way.
			kidHasSibling := n != len(kids)-1
			// An adopted child (pid 1's) renders where its parent did, so it
			// adds no column of its own.
			if entry.pid == 1 {
				walk(kid, prefix, kidHasSibling)
				continue
			}
			walk(kid, childPrefix(prefix, hasSibling), kidHasSibling)
		}
	}
	for index := len(ordered) - 1; index >= 0; index-- {
		if printed[index] || inTable[ordered[index].ppid] {
			continue
		}
		walk(index, "", false)
	}
	return rows
}

// childPrefix is the ladder a row passes to its children: its own prefix with
// the connector replaced by the bar that runs down to its siblings — four
// spaces when it is the last of them — and then the next level's connector.
// That is ps's own spelling: " \_ " for the connector, " |  " for the bar.
func childPrefix(prefix string, hasSibling bool) string {
	const (
		connector = ` \_ `
		bar       = ` |  `
		gap       = "    "
	)
	if prefix == "" {
		return connector
	}
	if hasSibling {
		return prefix[:len(prefix)-len(connector)] + bar + connector
	}
	return prefix[:len(prefix)-len(connector)] + gap + connector
}

// psAuxForest renders the aux table in the forest order and shape of this
// tier's shell counterpart, `ps auxwwf`: same columns, with the hierarchy drawn
// in the COMMAND cell.
func psAuxForest(snap processSnapshot, now time.Time) []string {
	rows := forestRows(snap.entries)
	text := make([]string, 0, len(rows))
	for _, row := range rows {
		entry := row.entry
		entry.args = row.prefix + entry.args
		text = append(text, psAuxRow(entry, snap.boot, now, snap.uptime, snap.memTotal))
	}
	return text
}

// psAuxRow renders one auxww row: the shape every ps aux consumer (and the
// miner filter) matches on.
func psAuxRow(e procEntry, boot time.Time, now time.Time, uptime float64, memTotal int64) string {
	return fmt.Sprintf("%-8s %5d %4.1f %4.1f %6d %5d %-7s %-4s %-5s %6s %s",
		psUserCell(e.user), e.pid, e.cpuPercent(uptime), e.memPercent(memTotal),
		e.vsize/1024, e.rss*int64(os.Getpagesize())/1024,
		ttyName(e.ttyNr), e.psStatString(), e.startClock(boot, now),
		psTimeFormat(e.cpuSeconds()), e.args)
}

// psEfRow renders one `ps -ef` row.
func psEfRow(e procEntry, boot time.Time, now time.Time, uptime float64) string {
	c := int(e.cpuPercent(uptime) + 0.5)
	return fmt.Sprintf("%-8s %6d %6d %3d %-5s %-8s %6s %s",
		psUserCell(e.user), e.pid, e.ppid, c, e.startClock(boot, now),
		ttyName(e.ttyNr), psTimeFormat(e.cpuSeconds()), e.args)
}

// PsAux renders the auxww table with the hierarchy drawn in it: the same
// rows `ps auxwwf` prints, forest order, ladder, and all. This is the tier that
// answers in practice, so the local channel gets the columns and the tree from
// one panel.
func PsAux(ctx context.Context) (string, error) {
	snap := procSnapshot(ctx)
	if !snap.ok {
		return "", model.ErrTierUnavailable
	}
	now := time.Now()
	var b strings.Builder
	b.WriteString(psAuxHeader + "\n")
	for _, row := range psAuxForest(snap, now) {
		b.WriteString(row)
		b.WriteByte('\n')
	}
	return b.String(), snap.cutReason(ctx)
}

// PsEf renders the System V table.
func PsEf(ctx context.Context) (string, error) {
	snap := procSnapshot(ctx)
	if !snap.ok {
		return "", model.ErrTierUnavailable
	}
	now := time.Now()
	var b strings.Builder
	b.WriteString("UID          PID  PPID  C STIME TTY          TIME CMD\n")
	for _, e := range snap.entries {
		b.WriteString(psEfRow(e, snap.boot, now, snap.uptime))
		b.WriteByte('\n')
	}
	return b.String(), snap.cutReason(ctx)
}

// nativePsSort renders an aux table sorted by a column, ps --sort's shape; the
// machine facts arrive once, with the key computed once per row.
func nativePsSort(ctx context.Context,
	key func(e procEntry, uptime float64, memTotal int64) float64) (string, error) {
	snap := procSnapshot(ctx)
	if !snap.ok {
		return "", model.ErrTierUnavailable
	}
	entries := sortedByKey(snap.entries, func(e procEntry) float64 {
		return key(e, snap.uptime, snap.memTotal)
	})
	now := time.Now()
	var b strings.Builder
	b.WriteString(psAuxHeader + "\n")
	for _, e := range entries {
		b.WriteString(psAuxRow(e, snap.boot, now, snap.uptime, snap.memTotal))
		b.WriteByte('\n')
	}
	return b.String(), snap.cutReason(ctx)
}

// PsCPU is `ps aux --sort=-%cpu`.
func PsCPU(ctx context.Context) (string, error) {
	return nativePsSort(ctx, func(e procEntry, uptime float64, _ int64) float64 {
		return e.cpuPercent(uptime)
	})
}

// PsMem is `ps aux --sort=-%mem`.
func PsMem(ctx context.Context) (string, error) {
	return nativePsSort(ctx, func(e procEntry, _ float64, _ int64) float64 {
		return float64(e.rss)
	})
}

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
			e.vsize/1024, e.rss*int64(os.Getpagesize())/1024, e.shr*int64(os.Getpagesize())/1024,
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

// sortableEntry is one row with its sort key, computed once: a comparator that
// derives the key itself would recompute it twice per comparison.
type sortableEntry struct {
	entry procEntry
	key   float64
}

// sortedByKey returns the entries in descending key order. The input is not
// written to: the snapshot's entries are shared with every other check.
func sortedByKey(entries []procEntry, key func(procEntry) float64) []procEntry {
	rows := make([]sortableEntry, len(entries))
	for index, entry := range entries {
		rows[index] = sortableEntry{entry: entry, key: key(entry)}
	}
	slices.SortStableFunc(rows, func(a, b sortableEntry) int { return cmp.Compare(b.key, a.key) })
	sorted := make([]procEntry, len(rows))
	for index, row := range rows {
		sorted[index] = row.entry
	}
	return sorted
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

// Pstree renders the process tree from ppid links, pstree -ap's
// evidence in ASCII connectors.
func Pstree(ctx context.Context) (string, error) {
	snap := procSnapshot(ctx)
	if !snap.ok {
		return "", model.ErrTierUnavailable
	}
	return renderPstree(snap.entries), snap.cutReason(ctx)
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
