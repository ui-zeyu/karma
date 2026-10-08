package shape

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The shapers share one contract: a body they recognize becomes the table, a
// body they do not becomes nil untouched, and the table's columns line up.

// wordStarts is where each word of a line begins.
func wordStarts(line string) []int {
	var starts []int
	for _, at := range regexp.MustCompile(`\S+`).FindAllStringIndex(line, -1) {
		starts = append(starts, at[0])
	}
	return starts
}

// assertCells checks a rendered table cell by cell: each expected cell must
// sit exactly inside the column band the header's word starts draw — a blank
// cell leaves its band empty, and a value that drifted into a neighbour's
// band fails.
func assertCells(t *testing.T, table string, want [][]string) {
	t.Helper()
	rows := strings.Split(strings.TrimSuffix(table, "\n"), "\n")
	if len(rows) != len(want)+1 {
		t.Fatalf("the table has %d rows, want a header and %d", len(rows), len(want))
	}
	bands := wordStarts(rows[0])
	for r, cells := range want {
		line := rows[r+1]
		for c, cell := range cells {
			from, to := bands[c], len(line)
			if c+1 < len(bands) {
				to = bands[c+1]
			}
			if from > len(line) {
				t.Fatalf("row %q is shorter than its column %d", line, c)
			}
			if got := strings.TrimSpace(line[min(from, len(line)):min(to, len(line))]); got != cell {
				t.Fatalf("row %d column %d holds %q, want %q", r+1, c, got, cell)
			}
		}
	}
}

// A row wider than the header is what the table's own doc says it keeps: the
// extra cells are padded like any column before the last, and no column index
// runs off the measured widths.
func TestTableKeepsARowWiderThanItsHeader(t *testing.T) {
	table := NewTable("A", "B")
	table.Add("1", "2", "3", "4")
	want := "A  B\n1  2  3  4\n"
	if got := table.String(); got != want {
		t.Fatalf("table = %q, want %q", got, want)
	}
}

// fstab's six-field records become the columns the check's form draws, and every
// other line keeps its own bytes as a one-value record — the remark the form
// prints as a line rather than as a row with one cell filled.
func TestFstabReadsTheSixFieldsAndKeepsTheRemarks(t *testing.T) {
	body := "# /etc/fstab: static file system information.\n" +
		"LABEL=cloudimg-rootfs    /     ext4    discard,errors=remount-ro    0 1\n" +
		"LABEL=UEFI    /boot/efi    vfat    umask=0077    0 1\n"
	got := Fstab("/etc/fstab", body)
	if got == nil || got.Records == nil {
		t.Fatal("an fstab body with records should be read into them")
	}
	if !slices.Equal(got.Records.Header, FstabColumns) {
		t.Fatalf("columns = %v, want %v", got.Records.Header, FstabColumns)
	}
	if got.Text != body {
		t.Fatalf("the text is the file's own bytes:\n%q\nwant:\n%q", got.Text, body)
	}
	if len(got.Records.Rows) != 3 {
		t.Fatalf("one record per line: %d", len(got.Records.Rows))
	}
	if comment := got.Records.Rows[0]; len(comment.Fields) != 1 || comment.Fields[0].Value != "# /etc/fstab: static file system information." {
		t.Fatalf("a comment is one value: %+v", comment.Fields)
	}
	want := []string{"LABEL=cloudimg-rootfs", "/", "ext4", "discard,errors=remount-ro", "0", "1"}
	for index, value := range want {
		if got := got.Records.Rows[1].Fields[index].Value; got != value {
			t.Errorf("cell %d = %q, want %q", index, got, value)
		}
	}
}

// A body with no complete record has no table to draw, so it is declined whole
// and reaches the panel as the file wrote it.
func TestFstabDeclinesABodyWithNoRecord(t *testing.T) {
	for name, body := range map[string]string{
		"comments only": "# a comment\nhalf a record\n",
		"empty":         "",
	} {
		if got := Fstab("", body); got != nil {
			t.Errorf("%s should decline, got %q", name, got.Text)
		}
	}
}

// df's table is read from whichever df printed it: the columns are karma's own,
// the mount point takes the rest of the row, and a body that is not df's table
// is declined whole rather than read as a fragment of one.
func TestDfReadsTheTableFromEitherDf(t *testing.T) {
	gnu := "Filesystem      Size  Used Avail Use% Mounted on\n" +
		"/dev/vda1        40G   15G   25G  38% /\n" +
		"tmpfs           391M     0  391M   0% /dev/shm\n"
	got := Df("", gnu)
	if got == nil || got.Records == nil {
		t.Fatal("a df body should be read into records")
	}
	if !slices.Equal(got.Records.Header, DfColumns) {
		t.Fatalf("columns = %v, want %v", got.Records.Header, DfColumns)
	}
	// The header line is the form's to draw, so the text holds the rows alone —
	// one line per record, which is what the reading pairs them by.
	if want := "/dev/vda1        40G   15G   25G  38% /\ntmpfs           391M     0  391M   0% /dev/shm\n"; got.Text != want {
		t.Fatalf("text = %q, want the rows alone %q", got.Text, want)
	}
	if len(got.Records.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(got.Records.Rows))
	}
	want := []string{"/dev/vda1", "40G", "15G", "25G", "38%", "/"}
	for index, value := range want {
		if got := got.Records.Rows[0].Fields[index].Value; got != value {
			t.Errorf("cell %d = %q, want %q", index, got, value)
		}
	}
	if name := got.Records.Rows[0].Fields[5].Name; name != "Mounted on" {
		t.Errorf("the last cell is named %q, want the two-word column", name)
	}

	// Every df spells the cells between the two names differently: busybox has
	// Available for Avail, and df -P prints 1024-blocks/Used/Available/Capacity.
	for _, header := range []string{
		"Filesystem      Size  Used Available Use% Mounted on",
		"Filesystem     1024-blocks  Used Available Capacity Mounted on",
	} {
		if got := Df("", header+"\n/dev/vda1 40G 15G 25G 38% /\n"); got == nil {
			t.Errorf("the header %q is df's", header)
		}
	}
}

func TestDfDeclinesWhatIsNotItsTable(t *testing.T) {
	for name, body := range map[string]string{
		"another table":  "Filesystem  Type  Size  Used  Avail  Use%\n/dev/vda1 ext4 40G 15G 25G 38%\n",
		"no header":      "/dev/vda1  40G  15G  25G  38%  /\n",
		"a header alone": "Filesystem  Size  Used Avail Use% Mounted on\n",
		"a short row":    "Filesystem  Size  Used Avail Use% Mounted on\n/dev/vda1  40G  15G\n",
		"a blank row":    "Filesystem  Size  Used Avail Use% Mounted on\n/dev/vda1  40G  15G  25G  38%  /\n\n",
		// BSD's own df -h names ten cells: its rows carry three columns karma
		// does not draw, so the table is not this one.
		"bsd df -h": "Filesystem  Size  Used  Avail  Capacity  iused  ifree  %iused  Mounted on\n" +
			"/dev/disk1s5s1  234G  12G  100G  11%  1234567  0  0%  /\n",
	} {
		if got := Df("", body); got != nil {
			t.Errorf("%s should decline, got %q", name, got.Text)
		}
	}
}

func TestNeighTable(t *testing.T) {
	body := "10.0.0.1 dev eth0 lladdr 00:1c:42:00:00:18 router REACHABLE\n" +
		"fe80::99 dev eth0 FAILED\n"
	got := NeighTable("", body)
	if got == nil {
		t.Fatal("ip neigh rows should be shaped")
	}
	rows := strings.Split(got.Text, "\n")
	if rows[0] != "ADDRESS   DEV   LLADDR             FLAGS   STATE" {
		t.Fatalf("the header is %q", rows[0])
	}
	assertCells(t, got.Text, [][]string{
		{"10.0.0.1", "eth0", "00:1c:42:00:00:18", "router", "REACHABLE"},
		{"fe80::99", "eth0", "", "", "FAILED"},
	})
}

func TestNeighTableDeclinesUnknownWords(t *testing.T) {
	for _, body := range []string{
		"10.0.0.1 dev eth0 ref 12 REACHABLE\n",        // ip -s spelling this shaper does not know
		"10.0.0.1 dev eth0 used 0/0/0 STALE\n",        // statistics words
		"Address Hwtype HWaddress Flags Mask Iface\n", // arp -n's own table
	} {
		if got := NeighTable("", body); got != nil {
			t.Fatalf("an unfamiliar body should decline, shaped %q", got.Text)
		}
	}
}

func TestRouteTable(t *testing.T) {
	// The IPv6 rows carry the fields iproute2 adds and the in-process netlink
	// reader does not decode — a default preference, a route lifetime, a
	// nexthop id, a bare flag — and the shaper reads them out, so the table a
	// remote host gives is the table a local run gives.
	body := "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.5 metric 100\n" +
		"10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5 metric 100\n" +
		"::1 dev lo proto kernel metric 256 pref medium\n" +
		"fdb2:2c26:f4e4::/64 dev eth0 proto ra metric 100 expires 2591685sec pref medium\n" +
		"default nhid 1360112309 via fe80::ecff:ffff:feff:ffff dev eth0 proto ra metric 100 " +
		"expires 8960sec pref medium\n" +
		"10.0.0.0/8 via 10.0.0.1 dev eth0 onlink mtu 1500 from 10.0.0.5 tos 0x10\n"
	got := RouteTable("", body)
	if got == nil {
		t.Fatal("ip route rows should be shaped")
	}
	if header, want := strings.Fields(strings.Split(got.Text, "\n")[0]),
		[]string{"DEST", "VIA", "DEV", "PROTO", "SCOPE", "SRC", "METRIC"}; !slices.Equal(header, want) {
		t.Fatalf("the header is %q, want %q", header, want)
	}
	assertCells(t, got.Text, [][]string{
		{"default", "10.0.0.1", "eth0", "dhcp", "", "10.0.0.5", "100"},
		{"10.0.0.0/24", "", "eth0", "kernel", "link", "10.0.0.5", "100"},
		{"::1", "", "lo", "kernel", "", "", "256"},
		{"fdb2:2c26:f4e4::/64", "", "eth0", "ra", "", "", "100"},
		{"default", "fe80::ecff:ffff:feff:ffff", "eth0", "ra", "", "", "100"},
		{"10.0.0.0/8", "10.0.0.1", "eth0", "", "", "10.0.0.5", ""},
	})
}

func TestRouteTableDeclinesTheFallbackProbes(t *testing.T) {
	// route(8) and netstat -rn print their own aligned tables: no `ip route`
	// key word appears in a row, so the shaper hands the body back as the tool
	// wrote it.
	for _, body := range []string{
		"Kernel IP routing table\n" +
			"Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n",
		"0.0.0.0         172.17.239.253  0.0.0.0         UG    100    0        0 eth0\n",
		"10.1.2.0        172.17.239.253  255.255.255.0   U     100    0        0 eth0\n",
		"default         172.17.239.253  0.0.0.0         UG    0      0        0 eth0\n",
	} {
		if got := RouteTable("", body); got != nil {
			t.Fatalf("a fallback probe's table should decline, shaped %q", got.Text)
		}
	}
}

func TestAptHistoryBuildsDateAndCommandRows(t *testing.T) {
	body := "Start-Date: 2026-10-04  10:57:49\n" +
		"Commandline: apt-get -y autoremove --purge fwupd\n" +
		"End-Date: 2026-10-04  10:58:01\n" +
		"Start-Date: 2026-10-04  11:00:23\n" +
		"Install: foo:arm64 (1.0)\n" +
		"Commandline: apt-get install -y foo\n"
	got := AptHistory("/var/log/apt/history.log", body)
	if got == nil {
		t.Fatal("the apt history section should be shaped")
	}
	want := "2026-10-04 10:57:49  apt-get -y autoremove --purge fwupd\n" +
		"2026-10-04 11:00:23  apt-get install -y foo\n"
	if got.Text != want {
		t.Fatalf("apt history:\n%q\nwant:\n%q", got.Text, want)
	}
	if got := AptHistory("/var/log/dpkg.log", body); got != nil {
		t.Fatal("only the apt section is this shaper's")
	}
}

func TestHomeTreeDrawsTheWalk(t *testing.T) {
	body := "drwxr-x--- 5 lab lab 4096 Jul 29 17:40 /home\n" +
		"drwxr-x--- 5 lab lab 4096 Jul 29 17:40 /home/lab\n" +
		"-rw------- 1 lab lab 1929 Jul 29 17:49 /home/lab/.bash_history\n" +
		"-rw-r--r-- 1 lab lab 220 Jan 06 16:23 /home/lab/.bash_logout\n" +
		"drwx------ 2 lab lab 4096 Jul 29 13:41 /home/lab/.ssh\n" +
		"-rw------- 1 lab lab 99 Jul 29 13:41 /home/lab/.ssh/authorized_keys\n" +
		"drwxr-xr-x 2 lab lab 4096 Jan 06 16:23 /home/other user\n" +
		"-rw-r--r-- 1 lab lab 220 Jan 06 16:23 /home/other user/a file\n"
	got := HomeTree("", body)
	if got == nil {
		t.Fatal("listing rows should be drawn")
	}
	for _, want := range []string{
		"[drwxr-x--- lab lab 4096 Jul 29 17:40]  /home\n",
		"├── [drwxr-x--- lab lab 4096 Jul 29 17:40]  /home/lab\n",
		"│   ├── [-rw------- lab lab 1929 Jul 29 17:49]  /home/lab/.bash_history\n",
		"│   ├── [-rw-r--r-- lab lab 220 Jan 06 16:23]  /home/lab/.bash_logout\n",
		"│   └── [drwx------ lab lab 4096 Jul 29 13:41]  /home/lab/.ssh\n",
		"│       └── [-rw------- lab lab 99 Jul 29 13:41]  /home/lab/.ssh/authorized_keys\n",
		"└── [drwxr-xr-x lab lab 4096 Jan 06 16:23]  /home/other user\n",
		"    └── [-rw-r--r-- lab lab 220 Jan 06 16:23]  /home/other user/a file\n",
		"\n3 directories, 4 files\n",
	} {
		if !strings.Contains(got.Text, want) {
			t.Fatalf("the tree should contain %q\ngot:\n%s", want, got.Text)
		}
	}
	if got := HomeTree("", "not a listing row"); got != nil {
		t.Fatal("a body that does not parse should decline")
	}
	if got := HomeTree("", "/home\n├── [drwx------]  lab\n"); got != nil {
		t.Fatal("a body tree already drew passes through")
	}
}

func TestTreeRootFallsBackToTheParentWhenTheShortestIsAFile(t *testing.T) {
	tree := NewTree()
	tree.Add("/home/lab/karma", "[-rwxr-xr-x lab lab 1 Jan 06 16:23]  karma", false)
	if !strings.HasPrefix(tree.String(), "/home/lab\n") {
		t.Fatalf("a lone file hangs under its parent directory:\n%s", tree.String())
	}
}

// Two paths sharing nothing above the filesystem root must end there, not
// spin: this test is the regression for an infinite loop in the root search.
func TestTreeRootStopsAtTheFilesystemRoot(t *testing.T) {
	tree := NewTree()
	tree.Add("/a/karma", "[-rwxr-xr-x lab lab 1 Jan 06 16:23]  karma", false)
	tree.Add("/b/evil", "[-rwxr-xr-x lab lab 1 Jan 06 16:23]  evil", false)
	if !strings.HasPrefix(tree.String(), "/\n") {
		t.Fatalf("paths with nothing in common root at the filesystem root:\n%s", tree.String())
	}
}
