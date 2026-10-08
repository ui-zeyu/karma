// tests for the in-process system reads: the logind session count procps uses
// for the uptime banner's user figure, and free's table.

package native

import (
	"testing"

	"github.com/prometheus/procfs"
)

// freeTable prints free -h's three lines in the tool's own widths, and derives
// used from MemAvailable. The fixture is a reading taken from a lab host (procps
// 4 prints the same arithmetic for it), with the pointer fields the file's
// figures arrive as.
func TestFreeTable(t *testing.T) {
	ptr := func(value uint64) *uint64 { return &value }
	fixture := func() procfs.Meminfo {
		return procfs.Meminfo{
			MemTotal: ptr(2012716), MemFree: ptr(137960), MemAvailable: ptr(1616344),
			Buffers: ptr(27184), Cached: ptr(1380720), SReclaimable: ptr(172356),
			Shmem: ptr(4312), SwapTotal: ptr(0), SwapFree: ptr(0),
		}
	}
	const header = "               total        used        free      shared  buff/cache   available\n"
	const swap = "Swap:             0B          0B          0B\n"
	cases := []struct {
		name string
		edit func(*procfs.Meminfo)
		mem  string
	}{
		{"the host's own reading", func(*procfs.Meminfo) {},
			"Mem:           1.9Gi       387Mi       134Mi       4.2Mi       1.5Gi       1.5Gi\n"},
		// A kernel that reports no available figure (pre-3.14) has that figure
		// taken from MemFree, the way procps' own meminfo library does — and used
		// with it, which is the one cell procps 3.3 reads differently.
		{"a kernel without available", func(mi *procfs.Meminfo) { mi.MemAvailable = nil },
			"Mem:           1.9Gi       1.8Gi       134Mi       4.2Mi       1.5Gi       134Mi\n"},
		// An available figure the file cannot mean — a container's distorted
		// numbers — is read the same way.
		{"an impossible available figure", func(mi *procfs.Meminfo) {
			mi.MemAvailable = ptr(2012716 + 1)
			mi.MemFree = ptr(1000)
		}, "Mem:           1.9Gi       1.9Gi       1.0Mi       4.2Mi       1.5Gi       1.0Mi\n"},
	}
	for _, tc := range cases {
		mi := fixture()
		tc.edit(&mi)
		want := header + tc.mem + swap
		if got := freeTable(&mi); got != want {
			t.Errorf("%s:\n%q\nwant\n%q", tc.name, got, want)
		}
	}
	// A reading without a total is no memory view at all.
	noTotal := fixture()
	noTotal.MemTotal = nil
	if got := freeTable(&noTotal); got != "" {
		t.Errorf("a reading without MemTotal printed %q", got)
	}
	// A target with swap states its own row, in the same three cells.
	withSwap := fixture()
	withSwap.SwapTotal, withSwap.SwapFree = ptr(2097152), ptr(1048576)
	if got := freeTable(&withSwap); got != header+fixtureMemRow+swapGiRow {
		t.Errorf("a swap row printed %q", got)
	}
}

// fixtureMemRow is the Mem line of TestFreeTable's host reading, and swapGiRow
// the same host with two gibibytes of swap, half of it in use — so the swap
// case states the row it shares with the other three.
const (
	fixtureMemRow = "Mem:           1.9Gi       387Mi       134Mi       4.2Mi       1.5Gi       1.5Gi\n"
	swapGiRow     = "Swap:          2.0Gi       1.0Gi       1.0Gi\n"
)

// freeScale is procps 4's -h spelling, and the pairs below are one procps 4.0.4
// host's own free -h over a fixture /proc/meminfo (a bind-mounted file in a
// private mount namespace, one MemTotal per run): the implementation has to
// agree with the tool's own digits, not with a rounding rule of karma's.
// procps 3.3 is not a second opinion here — it truncates its reading to whole
// mebibytes before scaling, so the same fixture prints 0.0Ki and 4.0Mi there.
func TestFreeScale(t *testing.T) {
	cases := []struct {
		kib  int64
		want string
	}{
		{0, "0B"},
		{1, "1.0Ki"},
		{100, "100Ki"},
		{512, "512Ki"},
		{900, "900Ki"},
		{1000, "1.0Mi"},
		{1023, "1.0Mi"},
		{1024, "1.0Mi"},
		{1100, "1.1Mi"},
		{1500, "1.5Mi"},
		{1900, "1.9Mi"},
		{2047, "2.0Mi"},
		{2500, "2.4Mi"},
		{3000, "2.9Mi"},
		{4312, "4.2Mi"},
		{8000, "7.8Mi"},
		{10000, "9.8Mi"},
		// The tenth stops fitting in the column, so the count becomes a whole
		// number — and 9.999 Mi is not the 10 Mi of the row below it.
		{10239, "9Mi"},
		{10240, "10Mi"},
		{20000, "19Mi"},
		{100000, "97Mi"},
		{1000000, "976Mi"},
		{1048575, "1.0Gi"},
		{1048576, "1.0Gi"},
		{1200000, "1.1Gi"},
		{1500000, "1.4Gi"},
		{1572864, "1.5Gi"},
		{2000000, "1.9Gi"},
		{2048000, "2.0Gi"},
		{3000000, "2.9Gi"},
		{5000000, "4.8Gi"},
		{10485760, "10Gi"},
		{1073741824, "1.0Ti"},
		{2000000000, "1.9Ti"},
	}
	for _, tc := range cases {
		if got := freeScale(tc.kib); got != tc.want {
			t.Errorf("freeScale(%d) = %q, want %q", tc.kib, got, tc.want)
		}
	}
}

func TestSessionIsUser(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"user session", "UID=0\nUSER=root\nACTIVE=1\nCLASS=user\n", true},
		{"user-early", "UID=0\nCLASS=user-early\n", true},
		{"manager", "UID=0\nCLASS=manager-early\n", false},
		{"greeter", "UID=1000\nCLASS=greeter\n", false},
		{"no class", "UID=0\nUSER=root\n", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		if got := sessionIsUser([]byte(c.data)); got != c.want {
			t.Errorf("%s: sessionIsUser = %v, want %v", c.name, got, c.want)
		}
	}
}
