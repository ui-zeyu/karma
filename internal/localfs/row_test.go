// Tests for the ls -l row layer: the permission string, the epoch fields, the
// listing rows, and the forensics ls section.

package localfs

import (
	"os"
	"path/filepath"
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

// find %T@ prints ten decimal places; the cluster parser reads the field as one
// number either way, but the listing rows have to match the sh source's.
func TestEpochFracTenDigits(t *testing.T) {
	at := time.Unix(1791205135, 277378520)
	if got := EpochFrac(at); got != "1791205135.2773785200" {
		t.Errorf("EpochFrac = %q, want the host find's %q", got, "1791205135.2773785200")
	}
	if got := EpochFrac(time.Unix(1791205135, 0)); got != "1791205135.0000000000" {
		t.Errorf("whole second = %q", got)
	}
}

func TestListingRowsShapeAndOrder(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old")
	newer := filepath.Join(dir, "newer")
	writeTouched(t, old, time.Now().Add(-48*time.Hour))
	writeTouched(t, newer, time.Now())
	rows, err := listingRows(dir, 10, NewNameCache())
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
	capped, err := listingRows(dir, 1, NewNameCache())
	if err != nil {
		t.Fatal(err)
	}
	if len(capped) != 1 {
		t.Fatalf("head cap failed: %d rows", len(capped))
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
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("a.txt", link); err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimRight(
		LsRows([]string{second, link, first, filepath.Join(dir, "gone")}), "\n"), "\n")
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

func epochOf(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return EpochFrac(StatOf(info).Mtime)
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

// The listing's order is the ssh pipeline's: sort -rn over "epoch\trow", which
// orders by the epoch field and then by the whole row, and -r reverses both
// steps. A row of the same instant therefore comes out newest-first by text.
func TestListingOrderMirrorsSortRnTies(t *testing.T) {
	tied := []listedRow{
		{sec: 1759000000, nsec: 500, text: "1759000000.0000005000\t1759000000.0000005000\t-rw-r--r-- 1 root root 0 Jan  1 00:00 /d/a"},
		{sec: 1759000000, nsec: 500, text: "1759000000.0000005000\t1759000000.0000005000\t-rw-r--r-- 1 root root 0 Jan  1 00:00 /d/c"},
		{sec: 1759000000, nsec: 500, text: "1759000000.0000005000\t1759000000.0000005000\t-rw-r--r-- 1 root root 0 Jan  1 00:00 /d/b"},
	}
	slices.SortFunc(tied, listingOrder)
	var got []string
	for _, r := range tied {
		got = append(got, r.text[len(r.text)-1:])
	}
	if want := []string{"c", "b", "a"}; !slices.Equal(got, want) {
		t.Errorf("ties ordered %q, sort -rn prints %q", got, want)
	}
}

// The comparator's numeric key is the printed fraction itself, not a float
// re-reading of it: the two rows below differ by one nanosecond, below what a
// float64 can hold at today's epoch. With identical row text only the exact key
// can order them, so a single float64 would hand the pair back unchanged.
func TestListingOrderKeepsNanosecondsApart(t *testing.T) {
	const text = "1759000000.9999999980\t1759000000.9999999980\tsame"
	rows := []listedRow{
		{sec: 1759000000, nsec: 999999998, text: text},
		{sec: 1759000001, nsec: 0, text: "1759000001.0000000000\tnewer"},
		{sec: 1759000000, nsec: 999999999, text: text},
	}
	slices.SortFunc(rows, listingOrder)
	// the key as one number, so the expectation reads in time order
	var got []int
	for _, r := range rows {
		got = append(got, int(r.sec-1759000000)*1000000000+r.nsec)
	}
	if want := []int{1000000000, 999999999, 999999998}; !slices.Equal(got, want) {
		t.Errorf("key order %v, want %v (seconds and nanoseconds compared apart, descending)", got, want)
	}
}
