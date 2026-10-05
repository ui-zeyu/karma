// tests for the /proc process snapshot's pure parts: tty decoding, the ps
// row formats, stat modifiers, and the pstree render.

package linux

import (
	"os"
	"strings"
	"testing"
	"time"
)

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
	row := psAuxRow(e, boot, now, 24*3600, 16<<30)
	for _, want := range []string{"root", "2210", "pts/0", "Ss", "0:09", "bash -i"} {
		if !strings.Contains(row, want) {
			t.Errorf("aux row missing %q:\n%s", want, row)
		}
	}
	kernel := e
	kernel.args = "[" + kernel.comm + "]"
	row = psAuxRow(kernel, boot, now, 24*3600, 16<<30)
	if !strings.Contains(row, "[bash]") {
		t.Errorf("kernel thread args should stay bracketed:\n%s", row)
	}
}

func TestRenderPstree(t *testing.T) {
	entries := []procEntry{
		{pid: 1, ppid: 0, comm: "systemd"},
		{pid: 630, ppid: 1, comm: "accounts-daemon"},
		{pid: 948, ppid: 1, comm: "sshd"},
		{pid: 2200, ppid: 948, comm: "sshd"},
		{pid: 2210, ppid: 2200, comm: "bash", args: "-bash"},
	}
	tree := renderPstree(entries)
	want := []string{
		"systemd(1)",
		"|-accounts-daemon(630)",
		"`-sshd(948)",
		"  `-sshd(2200)",
		"    `-bash(2210) -bash",
	}
	lines := strings.Split(strings.TrimRight(tree, "\n"), "\n")
	if len(lines) != len(want) {
		t.Fatalf("pstree lines = %d, want %d:\n%s", len(lines), len(want), tree)
	}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("pstree line %d = %q, want %q", i, lines[i], w)
		}
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
