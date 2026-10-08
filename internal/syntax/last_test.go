// last(1)'s rows, and lastb's: the cells the two tools print, and the one cell a
// word-by-word pass cannot see.

package syntax

import (
	"testing"
)

// last's row is four cells, and the login time is one of them: the day's pad
// ("Thu Oct  8 07:14") is the blank a word-by-word pass splits on, which is how
// one login came out in four colors.
func TestLastPaintsTheLoginTimeAsOneCell(t *testing.T) {
	row := "lab      pts/44       10.211.55.2      Thu Oct  8 07:14 - 07:15  (00:01)"
	got := spansOf(row, styleLast(row))
	want := "lab=" + tableColumnStyles[0].FG + " pts/44=" + tableColumnStyles[1].FG +
		" 10.211.55.2=" + tableColumnStyles[2].FG + " Thu=" + tableColumnStyles[3].FG +
		" Oct=" + tableColumnStyles[3].FG + " 8=" + tableColumnStyles[3].FG +
		" 07:14=" + tableColumnStyles[3].FG
	if got != want {
		t.Fatalf("spans = %q, want %q", got, want)
	}
}

// A boot record's terminal is the two words last prints in the one cell, and the
// kernel it names in the host cell is a cell of its own.
func TestLastGroupsABootRecordsTerminal(t *testing.T) {
	row := "reboot   system boot  5.15.0-198-generic Thu Jan  1 00:00"
	got := spansOf(row, styleLast(row))
	want := "reboot=" + tableColumnStyles[0].FG + " system=" + tableColumnStyles[1].FG +
		" boot=" + tableColumnStyles[1].FG + " 5.15.0-198-generic=" + tableColumnStyles[2].FG +
		" Thu=" + tableColumnStyles[3].FG + " Jan=" + tableColumnStyles[3].FG +
		" 1=" + tableColumnStyles[3].FG + " 00:00=" + tableColumnStyles[3].FG
	if got != want {
		t.Fatalf("spans = %q, want %q", got, want)
	}
}

// A console login has no host, and its time still takes the time column's color:
// the cell's own color does not depend on the cells before it.
func TestLastPaintsAConsoleLoginsTime(t *testing.T) {
	row := "lab      tty1                            Thu Oct  8 07:14 - 07:15  (00:01)"
	got := spansOf(row, styleLast(row))
	want := "lab=" + tableColumnStyles[0].FG + " tty1=" + tableColumnStyles[1].FG +
		" Thu=" + tableColumnStyles[3].FG + " Oct=" + tableColumnStyles[3].FG +
		" 8=" + tableColumnStyles[3].FG + " 07:14=" + tableColumnStyles[3].FG
	if got != want {
		t.Fatalf("spans = %q, want %q", got, want)
	}
}

// The trailer naming where the records begin is a remark about the file, and a
// line with no login time is not a row of the table.
func TestLastLeavesTheTrailerPlain(t *testing.T) {
	for _, line := range []string{
		"wtmp begins Wed Jul 29 13:41:26 2026",
		"/var/log/btmp has no entries",
		"lab      pts/0        10.211.55.2      no such session",
	} {
		if spans := styleLast(line); spans != nil {
			t.Errorf("%q should carry no color: %+v", line, spans)
		}
	}
}
