// tests for the in-process system reads: the logind session count procps uses
// for the uptime banner's user figure, and free's table.

package native

import (
	"testing"

	"github.com/prometheus/procfs"
)

// freeTable prints free's three lines in the tool's own widths, and derives used
// from MemAvailable. The fixture is a reading taken from a lab host (procps 4
// prints the same arithmetic for it), with the pointer fields the file's figures
// arrive as.
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
	const swap = "Swap:              0           0           0\n"
	cases := []struct {
		name string
		edit func(*procfs.Meminfo)
		mem  string
	}{
		{"the host's own reading", func(*procfs.Meminfo) {},
			"Mem:         2012716      396372      137960        4312     1580260     1616344\n"},
		// A kernel that reports no available figure (pre-3.14) gets the reading the
		// file does support: free plus the page cache, and used as the total minus
		// that — the definition procps 3.3 used.
		{"a kernel without available", func(mi *procfs.Meminfo) { mi.MemAvailable = nil },
			"Mem:         2012716      294496      137960        4312     1580260     1718220\n"},
		// An impossible available figure is treated the same way.
		{"an impossible available figure", func(mi *procfs.Meminfo) {
			mi.MemAvailable = ptr(2012716 + 1)
			mi.MemFree = ptr(1000)
		}, "Mem:         2012716      431456        1000        4312     1580260     1581260\n"},
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
