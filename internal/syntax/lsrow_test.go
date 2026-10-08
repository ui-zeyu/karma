// The ls -l row has one shape (script.LSBodyPrintf) and two readers: the
// reading layers take a collection row apart with script.SplitLsBody (the
// cluster normalizer's column lookup), and the ls-l lexer paints one through its
// own regex. They are separate mechanisms on purpose — the regex also
// anchors the date column, which the split does not need — so this test holds
// them to the same reading of every row shape karma actually collects or meets
// from GNU ls.

package syntax

import (
	"slices"
	"strings"
	"testing"

	"karma/internal/script"
)

func TestLsLRowParsersAgree(t *testing.T) {
	rows := []string{
		// the collection's own rows: single spaces, symlink target glued to the path
		"-rw-r--r-- 1 root root 4096 Oct 06 12:00 /etc/hosts",
		"drwxr-xr-x 2 root root 4096 Jun  1 10:00 /tmp/.X11-unix",
		"lrwxrwxrwx 1 root root 7 Oct 06 12:00 /binusr/bin",
		"-rwsr-xr-x 1 root root 1100000 Oct 06 02:45 /.root",
		// GNU ls: padded columns, the two-space day, the ACL mark, and the year
		// form of an old entry
		"-rw-r--r--  1 root root     4096 Oct  6 12:00 /etc/hosts",
		"-rw-r--r--+ 1 root root     4096 Oct 06 12:00 /etc/hosts",
		"-rw-r--r--  1 root root     4096 Oct 06  2024 /etc/hosts",
		"lrwxrwxrwx  1 root root        7 Oct 06 12:00 /bin -> usr/bin",
		// a path with spaces survives both readers whole
		"-rw-r--r-- 1 root root 4096 Oct 06 12:00 /tmp/a b c",
	}
	for _, row := range rows {
		fields, ok := script.SplitLsBody(row)
		if !ok {
			t.Fatalf("the split must read every collected row shape: %q", row)
		}
		matched, ok := matchLine(lsLine, row)
		if !ok {
			t.Fatalf("the ls-l lexer must read every collected row shape: %q", row)
		}
		for _, column := range []struct {
			group string
			field string
		}{
			{"perms", fields[0]},
			{"size", fields[4]},
			{"name", fields[8]},
		} {
			if start, end, _ := matched.span(column.group); row[start:end] != column.field {
				t.Errorf("%q: the lexer's %s column is %q, the split's is %q",
					row, column.group, row[start:end], column.field)
			}
		}
		// The lexer's date column is the split's month, day and clock together;
		// column padding differs between the two producers, so the words are what
		// is compared.
		dateStart, dateEnd, _ := matched.span("date")
		date := row[dateStart:dateEnd]
		if got, want := strings.Fields(date), fields[5:8]; !slices.Equal(got, want) {
			t.Errorf("%q: the lexer's date is %q, the split's is %q", row, got, want)
		}
	}
}
