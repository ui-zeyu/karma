// The ps-shaped tiers: the System V table `ps -ef` prints — pstree's schema,
// read from /proc here and from the target's own ps by the sh source's parser —
// plus the CPU-ordered auxww view the ps check prints. The /proc read behind
// them is proctable.go.
//
// Every tier here renders the in-process listing, so no userspace interposition
// (an LD_PRELOAD hook in a wrapped ps, a PATH shadow) can reshape the evidence on
// the local channel. The one deliberate exception is hidden-procs, which keeps
// asking the host's own ps: its divergence from this listing is the tamper
// signal.

package native

import (
	"context"
	"fmt"
	"strconv"
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

// startClock renders ps's START/STIME cell: the clock for a process started
// today, the date ("Oct05") for an earlier day. The boundary is the local
// calendar day, not a 24-hour window: a host booted yesterday evening prints the
// date for every process of that boot, which is what the lab's own ps does.
func (e procEntry) startClock(boot time.Time, now time.Time) string {
	if boot.IsZero() {
		return "?"
	}
	start := boot.Add(time.Duration(e.starttime) * time.Second / clkTck)
	if start.After(now) {
		// A process that starts after the clock says now is a clock that
		// moved: ps reads it as an old start and prints the date.
		return start.Format("Jan02")
	}
	startYear, startMonth, startDay := start.Date()
	nowYear, nowMonth, nowDay := now.Date()
	if startYear == nowYear && startMonth == nowMonth && startDay == nowDay {
		return start.Format("15:04")
	}
	return start.Format("Jan02")
}

// psTimeFormat is TIME's mm:ss; minutes run past an hour (ps prints 188:20).
func psTimeFormat(secs float64) string {
	total := int(secs + 0.5)
	return fmt.Sprintf("%d:%02d", total/60, total%60)
}

// psEfTimeFormat is `ps -ef`'s TIME cell: hours, minutes and seconds, each two
// cells wide (aux's spelling above is that table's own column).
func psEfTimeFormat(secs float64) string {
	total := int(secs + 0.5)
	return fmt.Sprintf("%02d:%02d:%02d", total/3600, total/60%60, total%60)
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

// PsAuxColumns is the auxww table's columns, in ps's own order: the header the
// panel draws, and the name every field of a record carries. It is exported
// because it is the tier's schema — the check's table declaration is keyed by
// these names, and a fixture that builds a body by hand reads them from here.
var PsAuxColumns = []string{
	"USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "START", "TIME", "COMMAND",
}

// PsEfColumns is the System V table's columns — the schema `ps -ef` prints and
// the native read states, whichever source answers: the check's table
// declaration is keyed by these names, and the sh source's parser reads its
// pinned command back into exactly these.
var PsEfColumns = []string{"UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"}

// fields names a row's values in column order, so the values and the header
// they travel with cannot drift apart.
func fields(names, values []string) []model.Field {
	fields := make([]model.Field, len(values))
	for index, value := range values {
		name := ""
		if index < len(names) {
			name = names[index]
		}
		fields[index] = model.Field{Name: name, Value: value}
	}
	return fields
}

// psAuxRecords is the aux table as records, one row per process in the pid
// order the snapshot reads. The command line is the kernel's own spelling of
// it; the hierarchy is the pstree tier's business, drawn from the parent link.
func psAuxRecords(snap processSnapshot, now time.Time) []model.Record {
	records := make([]model.Record, 0, len(snap.entries))
	for _, entry := range snap.entries {
		records = append(records, model.Record{
			Fields: fields(PsAuxColumns, psAuxValues(entry, snap.boot, now, snap.uptime, snap.memTotal)),
		})
	}
	return records
}

// psAuxValues is one auxww row's values: what ps prints in each column, and
// none of the widths it pads them to — the panel's table decides those.
func psAuxValues(e procEntry, boot time.Time, now time.Time, uptime float64, memTotal int64) []string {
	return []string{
		psUserCell(e.user), strconv.Itoa(e.pid),
		fmt.Sprintf("%.1f", e.cpuPercent(uptime)), fmt.Sprintf("%.1f", e.memPercent(memTotal)),
		strconv.FormatInt(e.vsizeKiB(), 10), strconv.FormatInt(e.rssKiB(), 10),
		ttyName(e.ttyNr), e.psStatString(), e.startClock(boot, now),
		psTimeFormat(e.cpuSeconds()), e.args,
	}
}

// psEfValues is one `ps -ef` row's values.
func psEfValues(e procEntry, boot time.Time, now time.Time, uptime float64) []string {
	return []string{
		psUserCell(e.user), strconv.Itoa(e.pid), strconv.Itoa(e.ppid),
		strconv.Itoa(int(e.cpuPercent(uptime) + 0.5)),
		e.startClock(boot, now), ttyName(e.ttyNr), psEfTimeFormat(e.cpuSeconds()), e.args,
	}
}

// psEfRecords is the System V table as records.
func psEfRecords(snap processSnapshot, now time.Time) []model.Record {
	records := make([]model.Record, 0, len(snap.entries))
	for _, entry := range snap.entries {
		records = append(records, model.Record{
			Fields: fields(PsEfColumns, psEfValues(entry, snap.boot, now, snap.uptime)),
		})
	}
	return records
}

// PsEf reads the System V table: the same rows `ps -ef` prints — the account,
// the two links, the cpu tick, the clocks, the terminal, the accumulated time
// and the command line as the kernel spells it — handed over as the fields they
// are. It is the schema the sh source's parser reads back out of the target's
// own `ps -ef`.
func PsEf(ctx context.Context) (*model.RecordSet, error) {
	snap := procSnapshot(ctx)
	if !snap.ok {
		return nil, model.ErrTierUnavailable
	}
	set := &model.RecordSet{Header: PsEfColumns, Rows: psEfRecords(snap, time.Now())}
	return set, snap.cutReason(ctx)
}

// PsCPU is `ps aux --sort=-%cpu`, the ps check's in-process tier: the whole
// table, the busiest process first. ps --sort's shape, the machine facts
// arriving once with the key computed once per row.
func PsCPU(ctx context.Context) (*model.RecordSet, error) {
	snap := procSnapshot(ctx)
	if !snap.ok {
		return nil, model.ErrTierUnavailable
	}
	entries := sortedByKey(snap.entries, func(e procEntry) float64 {
		return e.cpuPercent(snap.uptime)
	})
	now := time.Now()
	rows := make([]model.Record, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, model.Record{
			Fields: fields(PsAuxColumns, psAuxValues(entry, snap.boot, now, snap.uptime, snap.memTotal)),
		})
	}
	return &model.RecordSet{Header: PsAuxColumns, Rows: rows}, snap.cutReason(ctx)
}
