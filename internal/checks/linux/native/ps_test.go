// tests for the /proc process snapshot's pure parts: tty decoding, the ps
// row formats, stat modifiers, the tree nodes, and the run's shared view.

package native

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"karma/internal/model"
	"karma/internal/runstate"
)

// A walk that a check's own deadline stopped is partial, and the tier says so:
// the panel reads as a timeout with the rows already read, instead of passing
// the fragment off as the whole process table.
func TestProcessTierReportsACutWalk(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ctx = runstate.WithStore(ctx)
	runstate.Memo(ctx, runstate.From(ctx), procSnapshotKey{}, func() processSnapshot {
		return processSnapshot{
			entries: []procEntry{
				{pid: 1, comm: "half", args: "half", state: 'S', numThreads: 1},
			},
			ok: true,
		}
	})
	set, err := PsAux(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cut walk should be reported, got %v", err)
	}
	if got, _ := set.Rows[0].Value("COMMAND"); got != "half" {
		t.Fatalf("the rows already read should stay: %+v", set.Rows)
	}
}

// The process tiers must read the run's one snapshot rather than walk /proc
// each; a value planted in the store's slot is what they print. The reordering
// tiers sort their own copy: the shared view stays in pid order for the next
// check.
func TestProcessTiersReadTheSharedSnapshot(t *testing.T) {
	ctx := runstate.WithStore(t.Context())
	runstate.Memo(ctx, runstate.From(ctx), procSnapshotKey{}, func() processSnapshot {
		return processSnapshot{
			entries: []procEntry{
				{pid: 1, comm: "quiet", args: "quiet --arg", state: 'S', numThreads: 1},
				{pid: 2, comm: "busy", args: "busy", state: 'R', numThreads: 1, utime: 100},
			},
			boot:     time.Unix(1_700_000_000, 0),
			uptime:   3600,
			memTotal: 1 << 30,
			ok:       true,
			complete: true,
		}
	})

	aux, err := PsAux(ctx)
	if err != nil {
		t.Fatalf("ps tier: %v", err)
	}
	if len(aux.Rows) != 2 {
		t.Fatalf("the ps tier should read the shared snapshot: %+v", aux.Rows)
	}
	for _, want := range []string{"quiet --arg", "busy"} {
		if !slices.ContainsFunc(aux.Rows, func(rec model.Record) bool {
			value, _ := rec.Value("COMMAND")
			return value == want
		}) {
			t.Fatalf("the ps tier should carry %q: %+v", want, aux.Rows)
		}
	}
	// The table is flat and in pid order, the way `ps auxww` prints it; the
	// hierarchy is the tree tier's business.
	if first, _ := aux.Rows[0].Value("COMMAND"); first != "quiet --arg" {
		t.Fatalf("the ps tier should read the snapshot in pid order: %+v", aux.Rows)
	}
	if strings.Contains(model.RecordsText(aux.Rows), `\_`) {
		t.Fatalf("the ps tier should carry no ladder: %q", model.RecordsText(aux.Rows))
	}
	tree, err := Pstree(ctx)
	if err != nil || len(tree.Rows) != 2 {
		t.Fatalf("pstree tier = %+v, %v", tree, err)
	}
	if !slices.ContainsFunc(tree.Rows, func(rec model.Record) bool {
		pid, _ := rec.Value("PID")
		parent, _ := rec.Value("PPID")
		return pid == "2" && parent == "0"
	}) {
		t.Fatalf("the tree tier should carry the parent link: %+v", tree.Rows)
	}

	sorted, err := PsCPU(ctx)
	if err != nil {
		t.Fatalf("ps-cpu tier: %v", err)
	}
	if first, _ := sorted.Rows[0].Value("COMMAND"); first != "busy" {
		t.Fatalf("the sorted tier should lead with the busiest process: %+v", sorted.Rows)
	}
	if got := procSnapshot(ctx).entries[0].comm; got != "quiet" {
		t.Fatalf("sorting a tier's own copy reordered the shared snapshot: %q first", got)
	}
}

// A walk the winning check had to cut short is that check's partial answer, not
// the run's view: a later check reads its own instead of publishing the
// fragment as a whole table.
func TestProcessSnapshotDropsACutWalk(t *testing.T) {
	ctx := runstate.WithStore(t.Context())
	const sentinel = 1 << 30
	runstate.Memo(ctx, runstate.From(ctx), procSnapshotKey{}, func() processSnapshot {
		return processSnapshot{entries: []procEntry{{pid: sentinel}}, ok: true}
	})
	for _, e := range procSnapshot(ctx).entries {
		if e.pid == sentinel {
			t.Fatal("a cut-short walk was published as the run's view")
		}
	}
}

func TestTtyName(t *testing.T) {
	cases := []struct {
		nr   int
		want string
	}{
		{0, "?"},
		{(136 << 8) | 3, "pts/3"},
		{(4 << 8) | 2, "tty2"},
		{(4 << 8) | 65, "ttyS1"},
		{(5 << 8), "tty"},
		{(253 << 8) | 7, "253:7"},
		// a minor past 255 carries its high bits at bit 12 (new_encode_dev)
		{(136 << 8) | 44 | (0x100 << 12), "pts/300"},
		{(136 << 8) | 0xe8 | (0x300 << 12), "pts/1000"},
		{(4 << 8) | 8 | (0x100 << 12), "ttyS200"},
	}
	for _, c := range cases {
		if got := ttyName(c.nr); got != c.want {
			t.Errorf("ttyName(%d) = %q, want %q", c.nr, got, c.want)
		}
	}
}

func TestPsStatString(t *testing.T) {
	cases := []struct {
		e    procEntry
		want string
	}{
		{procEntry{state: 'S', numThreads: 1}, "S"},
		{procEntry{state: 'R', sid: 42, tgid: 42, numThreads: 1}, "Rs"},
		{procEntry{state: 'S', sid: 7, tgid: 9, numThreads: 4}, "Sl"},
		{procEntry{state: 'S', sid: 7, tgid: 9, pgrp: 5, tpgid: 5, ttyNr: 34819, numThreads: 1}, "S+"},
		// a thread is not the session leader even when its tid matches the session
		{procEntry{state: 'S', sid: 7, tgid: 9, numThreads: 1}, "S"},
		{procEntry{state: 'I', nice: -5, numThreads: 1}, "I<"},
		{procEntry{state: 'S', nice: 10, numThreads: 1}, "SN"},
		{procEntry{state: 'S', lockKiB: 64, numThreads: 1}, "SL"},
		// every modifier at once, in procps' order
		{procEntry{state: 'S', nice: -1, lockKiB: 4, sid: 3, tgid: 3, numThreads: 2,
			pgrp: 8, tpgid: 8, ttyNr: 34819}, "S<Lsl+"},
	}
	for _, c := range cases {
		if got := c.e.psStatString(); got != c.want {
			t.Errorf("stat(%d) = %q, want %q", c.e.pid, got, c.want)
		}
	}
}

func TestPsUserCellTruncatesLongNames(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"root", "root"},
		{"systemd+", "systemd+"},        // already at the width
		{"www-data", "www-data"},        // exactly eight cells
		{"systemd-resolve", "systemd+"}, // cut to seven + the marker
		{"_chrony", "_chrony"},
	}
	for _, c := range cases {
		if got := psUserCell(c.name); got != c.want {
			t.Errorf("psUserCell(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestStartClockSpelling(t *testing.T) {
	now := time.Date(2026, 10, 5, 15, 0, 0, 0, time.UTC)
	boot := now.Add(-48 * time.Hour)
	fresh := procEntry{starttime: 47 * 3600 * clkTck} // 47h after boot = 1h ago
	old := procEntry{starttime: 60 * clkTck}
	if got := fresh.startClock(boot, now); got != "14:00" {
		t.Errorf("fresh start = %q, want 14:00", got)
	}
	if got := old.startClock(boot, now); got != boot.Add(60*time.Second).Format("Jan02") {
		t.Errorf("old start = %q, want %q", got, boot.Add(60*time.Second).Format("Jan02"))
	}
}

func TestPsAuxRowShape(t *testing.T) {
	now := time.Date(2026, 10, 5, 15, 0, 0, 0, time.UTC)
	boot := now.Add(-24 * time.Hour)
	e := procEntry{
		pid: 2210, ppid: 948, sid: 2210, tgid: 2210, pgrp: 2210, tpgid: 2200, ttyNr: (136 << 8), state: 'S',
		user: "root", comm: "bash", args: "bash -i",
		utime: 6 * clkTck, stime: 3 * clkTck, starttime: 23 * 3600 * clkTck,
		vsize: 25 << 20, rss: 4096, numThreads: 1,
	}
	rec := model.Record{Fields: fields(PsAuxColumns, psAuxValues(e, boot, now, 24*3600, 16<<30))}
	// The values are what ps prints in each column, and none of the widths it
	// pads them to: those are the table's business.
	for name, want := range map[string]string{
		"USER": "root", "PID": "2210", "TTY": "pts/0", "STAT": "Ss", "TIME": "0:09", "COMMAND": "bash -i",
	} {
		got, ok := rec.Value(name)
		if !ok || got != want {
			t.Errorf("%s = %q (present %v), want %q", name, got, ok, want)
		}
	}
	kernel := e
	kernel.args = "[" + kernel.comm + "]"
	rec = model.Record{Fields: fields(PsAuxColumns, psAuxValues(kernel, boot, now, 24*3600, 16<<30))}
	if got, _ := rec.Value("COMMAND"); got != "[bash]" {
		t.Errorf("kernel thread command = %q, want [bash]", got)
	}
}

// A tier answers with the fields themselves: the names, the column order and
// the values are what the reading layer judges and the form draws, with no text
// form in between.
func TestPsAuxBodyCarriesItsRecords(t *testing.T) {
	ctx := runstate.WithStore(t.Context())
	runstate.Memo(ctx, runstate.From(ctx), procSnapshotKey{}, func() processSnapshot {
		return processSnapshot{
			entries: []procEntry{
				{pid: 1, comm: "systemd", args: "/sbin/init", state: 'S', user: "root", numThreads: 1},
			},
			boot: time.Unix(1_700_000_000, 0), uptime: 3600, memTotal: 1 << 30, ok: true, complete: true,
		}
	})
	set, err := PsAux(ctx)
	if err != nil {
		t.Fatalf("ps tier: %v", err)
	}
	if len(set.Header) != len(PsAuxColumns) || set.Header[0] != "USER" {
		t.Fatalf("header = %v, want the aux columns", set.Header)
	}
	if len(set.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(set.Rows))
	}
	if got, _ := set.Rows[0].Value("COMMAND"); got != "/sbin/init" {
		t.Errorf("COMMAND = %q, want /sbin/init", got)
	}
	if text := model.RecordsText(set.Rows); !strings.Contains(text, "/sbin/init") {
		t.Errorf("the readable rendering should carry the row: %q", text)
	}
}

// The tree tier hands over the nodes and their links, and nothing that looks
// like a drawing: the nesting is the tree form's, so nothing here spells a
// ladder or a depth.
func TestPstreeReadsTheNodesAndTheirLinks(t *testing.T) {
	ctx := runstate.WithStore(t.Context())
	runstate.Memo(ctx, runstate.From(ctx), procSnapshotKey{}, func() processSnapshot {
		return processSnapshot{
			entries: []procEntry{
				{pid: 1, ppid: 0, comm: "systemd", args: "/sbin/init", state: 'S', user: "root", numThreads: 1},
				{pid: 948, ppid: 1, comm: "sshd", args: "/usr/sbin/sshd -D", state: 'S', user: "root", numThreads: 1},
				{pid: 2210, ppid: 948, comm: "bash", args: "-bash", state: 'S', user: "lab", numThreads: 1},
			},
			boot: time.Unix(1_700_000_000, 0), uptime: 3600, memTotal: 1 << 30, ok: true, complete: true,
		}
	})
	set, err := Pstree(ctx)
	if err != nil {
		t.Fatalf("pstree tier: %v", err)
	}
	if !slices.Equal(set.Header, PsTreeColumns) {
		t.Fatalf("header = %v, want the tree columns", set.Header)
	}
	want := []string{"1 0 root /sbin/init", "948 1 root /usr/sbin/sshd -D", "2210 948 lab -bash"}
	if len(set.Rows) != len(want) {
		t.Fatalf("rows = %d, want %d: %+v", len(set.Rows), len(want), set.Rows)
	}
	for index, want := range want {
		if got := set.Rows[index].LineText(); got != want {
			t.Errorf("row %d = %q, want %q", index, got, want)
		}
	}
	if strings.Contains(model.RecordsText(set.Rows), `\_`) {
		t.Errorf("the tier should hand over nodes, not a drawn ladder: %q", model.RecordsText(set.Rows))
	}
}

func TestUpDuration(t *testing.T) {
	cases := []struct {
		secs float64
		want string
	}{
		{5 * 60, "5 min"},
		{0, "0 min"},
		// procps right-aligns the hours in two cells
		{3*3600 + 12*60, " 3:12"},
		{26*3600 + 5*60, "1 day,  2:05"},
		{10*24*3600 + 3600, "10 days,  1:00"},
		{97*24*3600 + 11*3600 + 44*60, "97 days, 11:44"},
		// a whole day and change: no hour part, the minutes stand alone
		{2*24*3600 + 20*60, "2 days, 20 min"},
	}
	for _, c := range cases {
		if got := upDuration(c.secs); got != c.want {
			t.Errorf("upDuration(%v) = %q, want %q", c.secs, got, c.want)
		}
	}
}

func TestMemPercentIsTenths(t *testing.T) {
	// procps: rss_bytes * 1000 / MemTotal_bytes with integer truncation. A host
	// of 1000 pages and a process holding six of them is at 0.6% — the page
	// size cancels, so the expectation holds on any host.
	memTotal := int64(1000) * int64(os.Getpagesize())
	if got := (procEntry{rss: 6}).memPercent(memTotal); got != 0.6 {
		t.Errorf("memPercent = %v, want 0.6", got)
	}
	if got := (procEntry{rss: 0}).memPercent(memTotal); got != 0 {
		t.Errorf("empty process = %v, want 0", got)
	}
	// the column caps at 99.9, so nothing prints as 100.0
	if got := (procEntry{rss: 1 << 40}).memPercent(memTotal); got != 99.9 {
		t.Errorf("oversized = %v, want 99.9", got)
	}
	if got := (procEntry{rss: 100}).memPercent(0); got != 0 {
		t.Errorf("unknown total = %v, want 0", got)
	}
}
