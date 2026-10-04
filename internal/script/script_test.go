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
