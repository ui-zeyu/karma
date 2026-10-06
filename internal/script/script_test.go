package script

import (
	"strings"
	"testing"
)

func TestQuote(t *testing.T) {
	cases := []struct{ word, want string }{
		{"", `''`},
		{"abc", "abc"},
		{"a@b%c+d=e:f,g.h/i-j_9", "a@b%c+d=e:f,g.h/i-j_9"},
		{"a b", "'a b'"},
		{"it's", `'it'\''s'`},
		{"$HOME", "'$HOME'"},
		{"a;b|c&", "'a;b|c&'"},
		{"*glob*", "'*glob*'"},
	}
	for _, c := range cases {
		if got := Quote(c.word); got != c.want {
			t.Errorf("Quote(%q) = %q, want %q", c.word, got, c.want)
		}
	}
}

// Join is the single escaping point for SSH command rendering: the whole argv is closed in single quotes, embedded quotes continued.
func TestJoin(t *testing.T) {
	got := Join([]string{"/bin/sh", "-c", "echo 'hi'"})
	want := `/bin/sh -c 'echo '\''hi'\'''`
	if got != want {
		t.Fatalf("Join = %q, want %q", got, want)
	}
}

func TestWordList(t *testing.T) {
	paths := []string{"/a", "/b", "/c", "/d", "/e"}
	got := WordList(paths)
	rows := strings.Split(got, " \\\n")
	if len(rows) != 2 {
		t.Fatalf("5 paths should wrap into two lines: %q", got)
	}
	if rows[0] != "/a /b /c /d" || rows[1] != "         /e" {
		t.Fatalf("wrong word-list wrap shape: %q", got)
	}
}

func TestListingSections(t *testing.T) {
	got := ListingSections([]string{"/etc/cron.d", "/var/spool/cron/*"}, 100)
	for _, want := range []string{
		"for d in /etc/cron.d /var/spool/cron/*; do",
		`echo "== $d"`,
		"LC_ALL=C find \"$d\"",
		"head -n 100",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q: %q", want, got)
		}
	}
}

func TestReadFiles(t *testing.T) {
	quiet := ReadFiles([]string{"/etc/fstab", "/proc/x"}, `cat "$f"`, true)
	if !strings.Contains(quiet, `[ -f "$f" ]`) || !strings.Contains(quiet, `echo "== $f"`) {
		t.Fatalf("missing guard or section header: %q", quiet)
	}
	if !strings.Contains(quiet, `cat "$f" 2>/dev/null`) {
		t.Fatalf("quiet should discard stderr: %q", quiet)
	}
	loud := ReadFiles([]string{"/etc/rc.local"}, `cat "$f"`, false)
	if strings.Contains(loud, "2>/dev/null") {
		t.Fatalf("non-quiet should carry no redirect: %q", loud)
	}
}

// The ls -l body split is the reading side's single definition of the row
// shape: columns are separated by runs of spaces, and the path keeps its own.
func TestSplitLsBody(t *testing.T) {
	cases := []struct {
		name string
		row  string
		want []string
	}{
		{
			"single spaces, as find -printf prints",
			"-rw-r--r-- 1 root root 4096 Jan 01 00:00 /etc/hosts",
			[]string{"-rw-r--r--", "1", "root", "root", "4096", "Jan", "01", "00:00", "/etc/hosts"},
		},
		{
			"padded, as GNU ls and AlignLsBodies print",
			"-rw-r--r--  1 root root    4096 Jan 01 00:00 /etc/hosts",
			[]string{"-rw-r--r--", "1", "root", "root", "4096", "Jan", "01", "00:00", "/etc/hosts"},
		},
		{
			"a path may hold spaces itself",
			"-rw-r--r-- 1 root root 4096 Jan 01 00:00 /tmp/my file.txt",
			[]string{"-rw-r--r--", "1", "root", "root", "4096", "Jan", "01", "00:00", "/tmp/my file.txt"},
		},
	}
	for _, c := range cases {
		fields, ok := SplitLsBody(c.row)
		if !ok {
			t.Errorf("%s: should split: %q", c.name, c.row)
			continue
		}
		if len(fields) != len(c.want) {
			t.Errorf("%s: %d fields, want %d: %q", c.name, len(fields), len(c.want), fields)
			continue
		}
		for i := range c.want {
			if fields[i] != c.want[i] {
				t.Errorf("%s: field %d = %q, want %q", c.name, i, fields[i], c.want[i])
			}
		}
	}
	for _, bad := range []string{"", "garbage", "-rw-r--r-- 1 root root", "-rw-r--r-- 1 root root 4096 Jan 01 00:00 "} {
		if fields, ok := SplitLsBody(bad); ok {
			t.Errorf("%q should not split into nine columns: %q", bad, fields)
		}
	}
	// a section holds rows that are not listings: a grep hit must not be read
	// as an ls -l row and padded
	hit := "/etc/udev/rules.d/50-x.rules:12:ACTION==\"add\", RUN+=\"/bin/sh -c echo x\""
	if fields, ok := SplitLsBody(hit); ok {
		t.Errorf("a grep hit should not split as a listing row: %q", fields)
	}
	// the platform's trailing attribute mark is part of the column
	withMark := "drwxr-xr-x+ 2 root root 4096 Jan 01 00:00 /etc/ssh"
	if fields, ok := SplitLsBody(withMark); !ok || fields[0] != "drwxr-xr-x+" {
		t.Errorf("an ACL mark belongs to the permission column: %q %v", fields, ok)
	}
}

// Alignment lines the numeric and name columns up over a whole listing, passes
// an unusual row through, leaves a single row alone, and is stable: an already
// aligned listing splits and re-renders unchanged.
func TestAlignLsBodies(t *testing.T) {
	rows := []string{
		"-rw-r--r-- 1 root root 100 Jan 01 00:00 /a/b",
		"drwxr-xr-x 20 yuyy wheel 1024 Jan 01 00:00 /c",
	}
	want := []string{
		"-rw-r--r--  1 root root   100 Jan 01 00:00 /a/b",
		"drwxr-xr-x 20 yuyy wheel 1024 Jan 01 00:00 /c",
	}
	aligned := AlignLsBodies(rows)
	for i := range want {
		if aligned[i] != want[i] {
			t.Errorf("row %d = %q, want %q", i, aligned[i], want[i])
		}
	}
	if again := AlignLsBodies(aligned); again[0] != want[0] || again[1] != want[1] {
		t.Errorf("alignment should be stable: %q", again)
	}
	if single := AlignLsBodies(rows[:1]); single[0] != rows[0] {
		t.Errorf("a single row has nothing to line up with: %q", single[0])
	}
	mixed := AlignLsBodies([]string{rows[0], "not a listing row", rows[1]})
	if mixed[1] != "not a listing row" || mixed[0] != want[0] {
		t.Errorf("an unusual row passes through and the rest still align: %q", mixed)
	}
	// A symlink's target follows the path with no arrow (find's %l), and the
	// link's size is the target's length: alignment separates the two the way
	// ls -l writes them. A path that holds spaces stays one column.
	linked := AlignLsBodies([]string{
		"lrwxrwxrwx 1 root root 7 Aug 16 02:02 /binusr/bin",
		"-rw-r--r-- 1 root root 100 Jan 01 00:00 /tmp/my file.txt",
	})
	if linked[0] != "lrwxrwxrwx 1 root root   7 Aug 16 02:02 /bin -> usr/bin" {
		t.Errorf("the symlink target was not separated: %q", linked[0])
	}
	if linked[1] != "-rw-r--r-- 1 root root 100 Jan 01 00:00 /tmp/my file.txt" {
		t.Errorf("a path with spaces changed: %q", linked[1])
	}
}
