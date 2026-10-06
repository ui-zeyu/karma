// The ps-shaped tiers: the auxww table with ps's own forest ladder drawn in the
// command column, the System V table, and the two sorted views. The /proc read
// behind them is proctable.go; top and pstree have their own files.
//
// Every tier here renders the in-process listing, so no userspace interposition
// (an LD_PRELOAD hook in a wrapped ps, a PATH shadow) can reshape the evidence on
// the local channel. The one deliberate exception is hidden-procs, which keeps
// asking the host's own ps: its divergence from this listing is the tamper
// signal.

package native

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"karma/internal/model"
)

// ttyName decodes stat's tty_nr: devpts majors are pts/N, major 4 the console
// and serial ttys, 0 no controlling terminal (ps's "?"). The kernel encodes the
// device with new_encode_dev — the minor's low byte at the bottom and its
// remaining bits at bit 12 — so a pty numbered past 255 carries a split minor
// (a jump host with hundreds of sessions).
func ttyName(nr int) string {
	if nr == 0 {
		return "?"
	}
	major := (nr >> 8) & 0xfff
	minor := (nr & 0xff) | ((nr >> 12) & 0xfff00)
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
		e.vsizeKiB(), e.rssKiB(),
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
