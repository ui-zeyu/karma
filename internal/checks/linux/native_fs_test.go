// tests for the /proc/self/mounts parsers and the df/mount/findmnt renders.

package linux

import (
	"strings"
	"testing"
)

func TestParseMountsUnescapesOctal(t *testing.T) {
	data := "/dev/sda1 /mnt/space\\040dir ext4 rw,relatime 0 0\n" +
		"proc /proc proc rw,nosuid 0 0\n" +
		"truncated line\n"
	rows := parseMounts(data)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].point != "/mnt/space dir" || rows[0].fstype != "ext4" || rows[0].opts != "rw,relatime" {
		t.Fatalf("row 0 = %+v", rows[0])
	}
	if rows[1].dev != "proc" {
		t.Fatalf("row 1 = %+v", rows[1])
	}
}

func TestHumanKiB(t *testing.T) {
	cases := []struct {
		kib  float64
		want string
	}{
		{0, "0"},
		{4, "4.0K"},
		{512, "512K"},
		{9.9 * 1024, "9.9M"},
		{99 * 1024, "99M"},
		{1.5 * 1024 * 1024, "1.5G"},
	}
	for _, c := range cases {
		if got := humanKiB(c.kib); got != c.want {
			t.Errorf("humanKiB(%.0f) = %q, want %q", c.kib, got, c.want)
		}
	}
}

func TestDfPercentRoundsUp(t *testing.T) {
	if got := dfPercent(1, 1024); got != 1 {
		t.Errorf("1 byte of 1KiB = %d%%, want 1", got)
	}
	if got := dfPercent(0, 1024); got != 0 {
		t.Errorf("empty = %d%%, want 0", got)
	}
	if got := dfPercent(1023*100, 1024*100); got != 100 { // 99.9% rounds to 100
		t.Errorf("99.9%% = %d, want 100", got)
	}
	if got := dfPercent(1, 0); got != 0 {
		t.Errorf("no total = %d, want 0", got)
	}
}

func TestDfLine(t *testing.T) {
	row := dfLine(mountRow{dev: "/dev/sda1", point: "/"}, 100<<20, 25<<20, 75<<20)
	want := "/dev/sda1         100M   25M   75M  25% /"
	if row != want {
		t.Errorf("df line = %q, want %q", row, want)
	}
}

func TestRenderMountRows(t *testing.T) {
	out := renderMountRows([]mountRow{{dev: "sysfs", point: "/sys", fstype: "sysfs", opts: "rw,nosuid"}})
	if strings.TrimSpace(out) != "sysfs on /sys type sysfs (rw,nosuid)" {
		t.Errorf("mount row = %q", out)
	}
}

func TestRenderFindmntRowsIndentsByDepth(t *testing.T) {
	out := renderFindmntRows([]mountRow{
		{dev: "/dev/sda2", point: "/", fstype: "ext4", opts: "rw"},
		{dev: "proc", point: "/proc", fstype: "proc", opts: "rw"},
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "/ ") || !strings.HasPrefix(lines[2], "  /proc ") {
		t.Fatalf("findmnt rows:\n%s", out)
	}
}
