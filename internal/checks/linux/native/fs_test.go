// tests for the /proc/self/mounts parsers and the df/mount/findmnt renders.

package native

import (
	"os"
	"slices"
	"strings"
	"testing"

	"karma/internal/runstate"
)

// The suid, sgid, and capability tiers must read the run's shared walk rather
// than start one of their own: a value planted in the store's slot is what
// they print.
func TestPrivWalkTiersReadSharedStore(t *testing.T) {
	ctx := runstate.WithStore(t.Context())
	planted := privWalk{
		lists: [][]string{{"/planted/suid"}, {"/planted/sgid", "/also/sgid"}},
		caps:  []string{"/planted/ping cap_net_raw=ep"},
	}
	runstate.Memo(ctx, runstate.From(ctx), privWalkKey{}, func() privWalk { return planted })

	suid, err := ModeBitScan(os.ModeSetuid, nil)(ctx)
	if err != nil {
		t.Fatalf("suid tier: %v", err)
	}
	if suid != "/planted/suid\n" {
		t.Fatalf("suid tier printed %q", suid)
	}
	sgid, err := ModeBitScan(os.ModeSetgid, nil)(ctx)
	if err != nil {
		t.Fatalf("sgid tier: %v", err)
	}
	if sgid != "/planted/sgid\n/also/sgid\n" {
		t.Fatalf("sgid tier printed %q", sgid)
	}
	if capsInProcess() {
		caps, err := FileCaps(nil)(ctx)
		if err != nil {
			t.Fatalf("caps tier: %v", err)
		}
		if caps != "/planted/ping cap_net_raw=ep\n" {
			t.Fatalf("caps tier printed %q", caps)
		}
	}
}

func TestPrivilegeRoots(t *testing.T) {
	rows := []mountRow{
		{dev: "/dev/sda1", point: "/", fstype: "ext4", opts: "rw,relatime"},
		{dev: "proc", point: "/proc", fstype: "proc", opts: "rw,nosuid"},
		{dev: "tmpfs", point: "/tmp", fstype: "tmpfs", opts: "rw,nosuid,nodev"},
		{dev: "/dev/sdb1", point: "/mnt/data", fstype: "xfs", opts: "rw"},
		{dev: "nfs-server:/export", point: "/mnt/nfs", fstype: "nfs4", opts: "rw"},
		{dev: "/dev/sda1", point: "/var/lib/lxc/x/rootfs", fstype: "ext4", opts: "rw"},
		{dev: "overlay", point: "/var/lib/docker/overlay2/x/merged", fstype: "overlay", opts: "rw"},
		{dev: "/dev/loop0", point: "/snap/core/1", fstype: "squashfs", opts: "ro"},
		{dev: "/dev/sdc1", point: "/run/media/usb", fstype: "vfat", opts: "rw"},
	}
	want := []string{"/", "/tmp", "/mnt/data", "/run/media/usb"}
	if got := privilegeRoots(rows, []string{"ext4", "xfs", "tmpfs", "vfat"}); !slices.Equal(got, want) {
		t.Fatalf("roots = %v, want %v", got, want)
	}
	if got := privilegeRoots(nil, []string{"ext4"}); !slices.Equal(got, []string{"/"}) {
		t.Fatalf("an empty mount table still walks the root: %v", got)
	}
}

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

func TestHumanKiBRoundsUp(t *testing.T) {
	// every expectation below was checked against the host's own df -h on
	// Ubuntu 26.04 (coreutils 9.7)
	cases := []struct {
		bytes uint64
		want  string
	}{
		{0, "0"},
		{4 << 10, "4.0K"},       // under ten keeps the decimal point
		{512 << 10, "512K"},     // at or above ten the integer stands alone
		{7577, "7.4K"},          // the ceiling of 7.399K
		{1084 << 10, "1.1M"},    // 1.058 MiB
		{2500 << 10, "2.5M"},    // 2.441 MiB → ceiling of the tenths digit
		{164644 << 10, "161M"},  // 160.78 MiB
		{249508 << 10, "244M"},  // 243.66 MiB
		{40901312 << 10, "40G"}, // 39.008 GiB: df prints 40G, not 39G
		{6759644 << 10, "6.5G"}, // 6.446 GiB
		{32251300 << 10, "31G"}, // 30.758 GiB
		{1048000, "1.0M"},       // 1023.4K rounds into the next unit
	}
	for _, c := range cases {
		if got := humanKiB(c.bytes); got != c.want {
			t.Errorf("humanKiB(%d) = %q, want %q", c.bytes, got, c.want)
		}
	}
}

func TestDfPercentRoundsUp(t *testing.T) {
	// the denominator is used + available (the space a non-root user can use),
	// so a filesystem with reserved blocks reads higher than used/total
	cases := []struct {
		used, avail uint64
		want        int
	}{
		{1, 1 << 20, 1},
		{0, 1 << 20, 0},
		{6759644, 32251300, 18}, // 17.33% → 18, the host's own reading
		{1084, 328208, 1},       // 0.33% → 1
		{2500, 820724, 1},       // 0.30% → 1
		{7577, 249856, 3},       // 2.94% → 3
		{99, 1, 99},             // 99% stays 99
		{0, 0, 0},               // nothing to divide by
	}
	for _, c := range cases {
		if got := dfPercent(c.used, c.avail); got != c.want {
			t.Errorf("dfPercent(%d, %d) = %d, want %d", c.used, c.avail, got, c.want)
		}
	}
}

func TestDfDummyFilesystems(t *testing.T) {
	cases := []struct {
		m    mountRow
		want bool
	}{
		{mountRow{fstype: "proc"}, true},
		{mountRow{fstype: "sysfs"}, true},
		{mountRow{fstype: "devpts"}, true},
		{mountRow{fstype: "debugfs"}, true},
		{mountRow{fstype: "mqueue"}, true},
		{mountRow{fstype: "none", opts: "rw,nosuid"}, true},
		{mountRow{fstype: "none", opts: "rw,bind"}, false}, // a bind mount is real
		// devtmpfs reports real blocks (/dev carries the nodes' size), so df has
		// to hide it by type: verified against GNU df, which drops it while `df -a`
		// lists it
		{mountRow{fstype: "devtmpfs"}, true},
		{mountRow{fstype: "tmpfs", opts: "rw"}, false},
		{mountRow{fstype: "ext4", opts: "rw,relatime"}, false},
	}
	for _, c := range cases {
		if got := dfDummy(c.m); got != c.want {
			t.Errorf("dfDummy(%+v) = %v, want %v", c.m, got, c.want)
		}
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
