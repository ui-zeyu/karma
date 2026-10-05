package native

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPermString(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		want string
	}{
		{0o644, "-rw-r--r--"},
		{0o755, "-rwxr-xr-x"},
		{os.ModeDir | 0o755, "drwxr-xr-x"},
		{os.ModeSymlink | 0o777, "lrwxrwxrwx"},
		{os.ModeSetuid | 0o755, "-rwsr-xr-x"},
		{os.ModeSetgid | 0o644, "-rw-r-Sr--"},
		{os.ModeSticky | os.ModeDir | 0o777, "drwxrwxrwt"},
		{os.ModeNamedPipe | 0o644, "prw-r--r--"},
		{os.ModeSocket | 0o755, "srwxr-xr-x"},
	}
	for _, c := range cases {
		if got := permString(c.mode); got != c.want {
			t.Errorf("permString(%v) = %s, want %s", c.mode, got, c.want)
		}
	}
}

func TestPathDepth(t *testing.T) {
	cases := []struct {
		root, path string
		want       int
	}{
		{"/", "/", 0},
		{"/", "/proc", 1},
		{"/", "/a/b", 2},
		{"/tmp", "/tmp", 0},
		{"/tmp", "/tmp/a", 1},
		{"/tmp", "/tmp/a/b", 2},
		{"/etc/skel/", "/etc/skel/x", 1},
	}
	for _, c := range cases {
		base := strings.TrimSuffix(c.root, "/")
		if base == "" {
			base = "/"
		}
		if got := pathDepth(base, c.path); got != c.want {
			t.Errorf("pathDepth(%s, %s) = %d, want %d", c.root, c.path, got, c.want)
		}
	}
}

func TestReadSectionsSkipsMissingAndTails(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.conf")
	missing := filepath.Join(dir, "missing.conf")
	if err := os.WriteFile(present, []byte("l1\nl2\nl3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// the glob stays literal on no match and is dropped by the [ -f ] guard
	got := ReadSections([]string{present, missing, dir + "/*.none"}, nil)
	want := "== " + present + "\nl1\nl2\nl3\n"
	if got != want {
		t.Fatalf("ReadSections body mismatch:\ngot  %q\nwant %q", got, want)
	}
	tailed := ReadSections([]string{present}, TailLines(2))
	if !strings.HasSuffix(tailed, "l2\nl3\n") || strings.Contains(tailed, "l1") {
		t.Fatalf("TailLines(2) kept the wrong window: %q", tailed)
	}
}

func TestListingRowsShapeAndOrder(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old")
	newer := filepath.Join(dir, "newer")
	writeTouched(t, old, time.Now().Add(-48*time.Hour))
	writeTouched(t, newer, time.Now())
	rows, err := listingRows(dir, 10, newNameCache())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("wanted two rows, got %d", len(rows))
	}
	// mtime descending: the newer entry first, its epoch leading the row
	if !strings.HasPrefix(rows[0], epochOf(newer)) {
		t.Fatalf("newer entry should lead, got %q", rows[0])
	}
	for _, row := range rows {
		parts := strings.SplitN(row, "\t", 3)
		if len(parts) != 3 || !strings.Contains(parts[0], ".") {
			t.Fatalf("row lacks the epoch-prefixed listing shape: %q", row)
		}
		fields := strings.Fields(parts[2])
		if len(fields) < 9 {
			t.Fatalf("ls body should hold permissions links owner group size date clock path: %q", parts[2])
		}
	}
	// head cap: one row survives a cap of 1
	capped, err := listingRows(dir, 1, newNameCache())
	if err != nil {
		t.Fatal(err)
	}
	if len(capped) != 1 {
		t.Fatalf("head cap failed: %d rows", len(capped))
	}
}

// Ls is the reader form of the listing rows: bare ls-l bodies (no epoch
// prefix), the same mtime-descending order, no cap, dot entries included, and
// a file operand prints its own row. A path list prints one section per path;
// a failed path leaves the others printed and its error with the caller.
func TestLsRowsAndFileOperand(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old")
	fresh := filepath.Join(dir, "fresh")
	writeTouched(t, old, time.Now().Add(-48*time.Hour))
	writeTouched(t, fresh, time.Now())

	got, err := Ls([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("wanted two rows, got %q", got)
	}
	// a single path prints bare rows: mtime descending, no epoch prefix, no
	// section header
	if !strings.HasSuffix(lines[0], " "+fresh) {
		t.Fatalf("the fresh entry should lead: %q", lines)
	}
	if !strings.HasSuffix(lines[1], " "+old) {
		t.Fatalf("the old entry should follow: %q", lines)
	}
	// the rows are listingRows with the epoch prefix cut off, not a second listing
	// (the columns are padded for display, so compare the fields)
	collected, err := listingRows(dir, 0, newNameCache())
	if err != nil {
		t.Fatal(err)
	}
	if len(collected) != len(lines) {
		t.Fatalf("Ls and listingRows diverged: %q vs %q", lines, collected)
	}
	for i, line := range lines {
		if fields := strings.SplitN(line, " ", 9); len(fields) == 9 {
			line = strings.Join(fields[:8], " ") + " " + fields[8]
		}
		want := rowBody(collected[i])
		if line != want {
			t.Fatalf("Ls row %d is not the panel body:\n got %q\nwant %q", i, line, want)
		}
	}

	// a file operand prints its own row; a symlink operand keeps the link row
	row, err := Ls([]string{fresh})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(row, "-rw") || !strings.HasSuffix(strings.TrimSuffix(row, "\n"), " "+fresh) {
		t.Fatalf("a file operand should print its own row: %q", row)
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink("fresh", link); err != nil {
		t.Skipf("symlinks are unavailable here: %v", err)
	}
	if row, err = Ls([]string{link}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(row, "l") || !strings.HasSuffix(strings.TrimSuffix(row, "\n"), "alias -> fresh") {
		t.Fatalf("a symlink operand should keep the link row: %q", row)
	}

	// a dot entry shows like find lists it
	hidden := filepath.Join(dir, ".env")
	writeTouched(t, hidden, time.Now().Add(-1*time.Hour))
	if got, err = Ls([]string{dir}); err != nil || !strings.Contains(got, hidden) {
		t.Fatalf("dot entries belong in the listing: %q (%v)", got, err)
	}

	// several paths print one section per path, the collection sections'
	// own header; a failed path keeps its section out while the rest print
	other := t.TempDir()
	otherFile := filepath.Join(other, "side")
	writeTouched(t, otherFile, time.Now())
	got, err = Ls([]string{dir, filepath.Join(dir, "missing"), other})
	if err == nil {
		t.Fatal("the missing path should surface its error")
	}
	if !strings.Contains(got, "== "+dir+"\n") || !strings.Contains(got, "== "+other+"\n") {
		t.Fatalf("each surviving path should head its own section: %q", got)
	}
	if !strings.Contains(got, " "+otherFile) || strings.Contains(got, "missing") {
		t.Fatalf("the good sections should print and only those: %q", got)
	}
}

// A listing's columns line up like ls -l: the date of every row starts in the
// same column even when sizes and link counts differ.
func TestLsColumnsAlign(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "tiny")
	large := filepath.Join(dir, "huge")
	if err := os.WriteFile(small, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(large, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	// one extra name: the two rows then differ in link count as well
	if err := os.Link(large, filepath.Join(dir, "huge2")); err != nil {
		t.Skipf("hard links are unavailable here: %v", err)
	}

	got, err := Ls([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("wanted several rows, got %q", got)
	}
	// every row's first eight columns occupy the same width, so the path starts
	// at one column whatever the link count and size are
	pathAt := -1
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 9 {
			t.Fatalf("row does not hold the ls -l fields: %q", line)
		}
		// the path is the row's tail: what follows the last column separator,
		// after the padding that lines the earlier columns up
		at := strings.LastIndex(line, " "+fields[8])
		if pathAt < 0 {
			pathAt = at
		} else if at != pathAt {
			t.Fatalf("the path column moved: %d vs %d\n%s", at, pathAt, got)
		}
		// the padding sits between the columns, never inside the path
		if !filepath.IsAbs(fields[8]) {
			t.Fatalf("the path should be untouched: %q", line)
		}
	}
}

func epochOf(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return epochFrac(statOf(info).mtime)
}

func writeTouched(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func TestWalkTreeDepthAndPrune(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var seen []string
	_ = walkTree(context.Background(), dir, 2, false, nil, func(path string, info os.FileInfo) bool {
		seen = append(seen, path)
		return true
	})
	// depth 2 = root, a, b — the file at depth 3 and directory c stay out
	if slices.ContainsFunc(seen, func(p string) bool { return strings.HasSuffix(p, "/f") }) {
		t.Fatalf("depth cap did not stop the walk: %v", seen)
	}
	pruned := map[string]bool{filepath.Join(dir, "a"): true}
	seen = nil
	_ = walkTree(context.Background(), dir, 0, false, func(path string, _ os.FileInfo) bool {
		return pruned[path]
	}, func(path string, info os.FileInfo) bool {
		seen = append(seen, path)
		return true
	})
	if slices.ContainsFunc(seen, func(p string) bool { return strings.HasSuffix(p, "b") }) {
		t.Fatalf("pruned directory was descended into: %v", seen)
	}
}

func TestGrepWalk(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(dir, "a.php"):                  "<?php eval($_POST['x']); ?>\nclean\n",
		filepath.Join(dir, "b.txt"):                  "eval($_POST['x'])\n",
		filepath.Join(dir, "skip.php"):               "a\x00b eval($_POST['x'])\n",
		filepath.Join(sub, "c.php"):                  "line\n<?php eval($_REQUEST['y']);\n",
		filepath.Join(dir, "node_modules", "d.php"):  "eval($_POST['x'])\n",
		filepath.Join(dir, ".git", "e.php"):          "eval($_POST['x'])\n",
		filepath.Join(sub, "vendor", "keep.inc.php"): "",
	}
	for path, body := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	opt := GrepScan{
		Pattern:     regexp.MustCompile(`eval\(\$_(POST|REQUEST)`),
		Includes:    []string{"*.php"},
		ExcludeDirs: []string{".git", "node_modules"},
	}
	hits := grepWalk(context.Background(), dir, opt)
	want := []string{
		filepath.Join(dir, "a.php") + ":1:",
		filepath.Join(sub, "c.php") + ":2:",
	}
	if len(hits) != len(want) {
		t.Fatalf("wanted %d hits, got %v", len(want), hits)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(hits[i], prefix) {
			t.Fatalf("hit %d = %q, want prefix %q", i, hits[i], prefix)
		}
	}
}

func TestVerifyChangedParsesMd5Flag(t *testing.T) {
	out := "??5?????? c /etc/passwd\n c /etc/shadow\n..5?????? c /usr/bin/sudo\n"
	got := verifyChanged(out)
	want := []string{"/etc/passwd", "/usr/bin/sudo"}
	if !slices.Equal(got, want) {
		t.Fatalf("verifyChanged = %v, want %v", got, want)
	}
}

// The forensics rows keep ls -l's own order (ls sorts its arguments) and its
// symlink arrow; a file that is gone costs only its row.
func TestLsRowsSortsAndKeepsLinkTargets(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.txt")
	second := filepath.Join(dir, "b.txt")
	link := filepath.Join(dir, "c-link")
	for _, path := range []string{second, first} {
		if err := writeFile(t, path, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("a.txt", link); err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimRight(
		lsRows([]string{second, link, first, filepath.Join(dir, "gone")}), "\n"), "\n")
	if len(rows) != 3 {
		t.Fatalf("wanted three rows (the missing file drops out), got %v", rows)
	}
	if !strings.HasSuffix(rows[0], " "+first) || !strings.HasSuffix(rows[1], " "+second) {
		t.Fatalf("rows should be sorted by path: %v", rows)
	}
	if !strings.HasSuffix(rows[2], "c-link -> a.txt") {
		t.Fatalf("symlink row should keep the arrow: %q", rows[2])
	}
}

func TestNativeSuidScanFiltersModeBit(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	marked := filepath.Join(dir, "marked")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marked, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The owner-execute bit stands in for the setuid/setgid bits the callers
	// pass: some filesystems (macOS temp volumes) strip the special bits, and
	// the filter is the same bit test either way.
	lists, caps, err := scanPrivFiles(context.Background(), []string{dir}, 0o100)
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 {
		t.Fatalf("scan returned %d bit lists, want 1", len(lists))
	}
	if !slices.Contains(lists[0], marked) || slices.Contains(lists[0], plain) {
		t.Fatalf("mode-bit scan window wrong: %v", lists[0])
	}
	// the same pass reads capabilities; a plain temp file carries none
	if len(caps) != 0 {
		t.Fatalf("capability rows on files without capabilities: %v", caps)
	}
}

func TestNativeMinerPsFilter(t *testing.T) {
	now := time.Now()
	snap := processSnapshot{
		entries: []procEntry{
			{pid: 1, user: "root", args: "xmrig --donate", state: 'S', numThreads: 1},
			{pid: 2, user: "user", args: "grep xmrig", state: 'S', numThreads: 1},
			{pid: 3, user: "user", args: "stratum+tcp://pool", state: 'S', numThreads: 1},
			{pid: 4, user: "user", args: "bash", state: 'S', numThreads: 1},
		},
		boot:     now.Add(-time.Hour),
		uptime:   3600,
		memTotal: 1 << 30,
		ok:       true,
		complete: true,
	}
	var b strings.Builder
	for _, line := range minerPsLines(snap, now, regexp.MustCompile(`\bxmrig\b|stratum\+?(tcp|ssl):`)) {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	body := b.String()
	if !strings.Contains(body, "xmrig --donate") || !strings.Contains(body, "stratum+tcp") {
		t.Fatalf("miner ps window lost hits:\n%s", body)
	}
	if strings.Contains(body, "grep") || strings.Contains(body, "bash") {
		t.Fatalf("miner ps window kept noise:\n%s", body)
	}
}

// shellGlob must not hand back dot-file names the shell's own glob would skip:
// /etc/cron.d/* has a .placeholder the script tier never sees.
func TestShellGlobSkipsDotFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"job", ".placeholder", ".hidden"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := shellGlob(filepath.Join(dir, "*"))
	if len(got) != 1 || filepath.Base(got[0]) != "job" {
		t.Errorf("glob * = %v, want just the plain name", got)
	}
	got = shellGlob(filepath.Join(dir, ".*"))
	if len(got) != 2 {
		t.Errorf("glob .* = %v, want both dot names", got)
	}
	if got = shellGlob(filepath.Join(dir, "*.nomatch")); len(got) != 0 {
		t.Errorf("non-matching glob = %v, want nothing", got)
	}
}

// The kernel stores a priority in front of every ring-buffer line; dmesg
// prints the line without it.
func TestStripSyslogPriority(t *testing.T) {
	body := "<6>[    0.000000] Linux version 7.0.0\n<4>[   12.5] audit: denied\n" +
		"[    9.9] already bare\n<5>no bracket close\nnot <6> a prefix\n"
	want := "[    0.000000] Linux version 7.0.0\n[   12.5] audit: denied\n" +
		"[    9.9] already bare\nno bracket close\nnot <6> a prefix\n"
	if got := stripSyslogPriority(body); got != want {
		t.Errorf("stripSyslogPriority = %q, want %q", got, want)
	}
	if got := stripSyslogPriority("plain\n"); got != "plain\n" {
		t.Errorf("plain body changed: %q", got)
	}
}

func TestLsmodRows(t *testing.T) {
	data := "udp_diag 12288 0 - Live 0x0000000000000000\n" +
		"inet_diag 24576 2 tcp_diag,udp_diag Live 0x0000000000000000\n" +
		"broken\n"
	want := "Module                  Size  Used by\n" +
		"udp_diag               12288  0\n" +
		"inet_diag              24576  2 tcp_diag,udp_diag\n"
	if got := lsmodRows(data); got != want {
		t.Errorf("lsmodRows:\n%q\nwant:\n%q", got, want)
	}
}

// find %T@ prints ten decimal places; the cluster parser reads the field as one
// number either way, but the listing rows have to match the script tier's.
func TestEpochFracTenDigits(t *testing.T) {
	at := time.Unix(1791205135, 277378520)
	if got := epochFrac(at); got != "1791205135.2773785200" {
		t.Errorf("epochFrac = %q, want the host find's %q", got, "1791205135.2773785200")
	}
	if got := epochFrac(time.Unix(1791205135, 0)); got != "1791205135.0000000000" {
		t.Errorf("whole second = %q", got)
	}
}
