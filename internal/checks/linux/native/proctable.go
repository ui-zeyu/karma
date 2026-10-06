// The /proc process table behind every ps-shaped tier: one snapshot per run —
// four reads per process, shared through the run's store — and the arithmetic
// that turns its fields into the columns ps prints.

package native

import (
	"cmp"
	"context"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/procfs"

	"karma/internal/localfs"
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
// memory totals all come through it. Every accessor reports its own error, so a
// host without /proc falls through to the next tier of its check without a
// separate probe.
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
	// ok is false when /proc is absent: the table could not be read at all.
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
	snap := runstate.Memo(ctx, store, procSnapshotKey{}, func() processSnapshot {
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
	rssBytes := e.rssBytes()
	if rssBytes >= memTotal {
		return 99.9
	}
	return float64(rssBytes*1000/memTotal) / 10
}

// rssBytes, vsizeKiB, rssKiB and shrKiB are the table columns' units: /proc
// reports rss and shr in pages and vsize in bytes, while ps prints KiB.
func (e procEntry) rssBytes() int64 { return e.rss * int64(os.Getpagesize()) }
func (e procEntry) vsizeKiB() int64 { return e.vsize / 1024 }
func (e procEntry) rssKiB() int64   { return e.rssBytes() / 1024 }
func (e procEntry) shrKiB() int64   { return e.shr * int64(os.Getpagesize()) / 1024 }

// cpuSeconds is the accumulated CPU time in seconds (ps's TIME column).
func (e procEntry) cpuSeconds() float64 {
	return float64(e.utime+e.stime) / clkTck
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
