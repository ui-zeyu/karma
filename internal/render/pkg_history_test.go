// The pkg-history lexer: the records the check keeps are context, so they carry
// no severity and the coloring has to do the reading — the command line's
// program and its arguments are told apart.

package render

import (
	"strings"
	"testing"
)

// spansOf returns the spans as "text=color" pairs, in order, for a compact
// comparison in the table below.
func spansOf(line string, spans []paintSpan) string {
	out := make([]string, 0, len(spans))
	for _, span := range spans {
		out = append(out, line[span.Start:span.End]+"="+string(span.Style.fg))
	}
	return strings.Join(out, " ")
}

func TestPkgHistoryPaintsACommandLine(t *testing.T) {
	line := "Commandline: apt-get install --reinstall login -y"
	got := spansOf(line, stylePkgHistory(line))
	want := "Commandline:=244 apt-get=4 --reinstall=2 -y=2"
	if got != want {
		t.Fatalf("spans = %q, want %q", got, want)
	}
}

func TestPkgHistoryPaintsDpkgRecords(t *testing.T) {
	cases := []struct{ line, want string }{
		{"2025-06-01 10:20:11 install nginx:amd64 <none> 1.18.0-1",
			"2025-06-01 10:20:11=244 install=6 nginx=4 :amd64= <none> 1.18.0-1="},
		{"2025-06-01 10:20:12 upgrade login:amd64 1:4.8-1 1:4.8-1.1",
			"2025-06-01 10:20:12=244 upgrade=6 login=4 :amd64= 1:4.8-1 1:4.8-1.1="},
	}
	for _, c := range cases {
		got := spansOf(c.line, stylePkgHistory(c.line))
		// The dim spans carry no color of their own (faint only), so the tail
		// is compared as plain text.
		want := c.want
		if got != want {
			t.Errorf("%q: spans = %q, want %q", c.line, got, want)
		}
	}
}

// The apt "Start-Date" row is a label and a timestamp: the label is muted and
// the timestamp keeps the body color, so no date reads as a command.
func TestPkgHistoryLeavesTheStartDateValuePlain(t *testing.T) {
	line := "Start-Date: 2025-06-01  10:20:11"
	spans := stylePkgHistory(line)
	if len(spans) != 1 || spans[0].Start != 0 || spans[0].End != len("Start-Date:") {
		t.Fatalf("spans = %+v, want the key alone", spans)
	}
}

// A row of dnf's history table is a ` | `-segmented line: the pipe lexer paints
// it, and every other line shape stays plain rather than being colored by guess.
func TestPkgHistoryFallsThroughToTheTableAndPlainText(t *testing.T) {
	row := `     1 | install -y nginx | 2025-06-01 10:20 | Install        |    1`
	if got := spansOf(row, stylePkgHistory(row)); !strings.Contains(got, "install -y nginx=") {
		t.Fatalf("a dnf row was not painted as a pipe table: %q", got)
	}
	if spans := stylePkgHistory("a plain remark"); len(spans) != 0 {
		t.Fatalf("a plain line got spans: %+v", spans)
	}
}
