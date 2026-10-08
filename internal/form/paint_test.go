// The span stacker: one line painted by a stack of spans, the way a lexer's
// coloring and a rule's hits land on the same row.

package form

import (
	"regexp"
	"strings"
	"testing"

	"karma/internal/model"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func plainText(s string) string { return ansi.ReplaceAllString(s, "") }

func contains(text, part string) bool { return strings.Contains(text, part) }

// The ls -l row's own paint, in this package's terms: the shape a lexer's spans
// have on every listing row, so the benchmark measures the stacker rather than
// one lexer.
func listingSpans(row string) []Span {
	muted := MutedPaint()
	return []Span{
		{Start: 0, End: len(row), Style: muted},
		{Start: 1, End: 4, Style: ColumnPaint(1)},
		{Start: 12, End: 16, Style: ColumnPaint(3)},
		{Start: 17, End: 29, Style: ColumnPaint(2)},
		{Start: 30, End: len(row), Style: ColumnPaint(0)},
	}
}

// BenchmarkPaintLine isolates the span stacker: a row with the ls-l lexer's
// spans for every permission bit, the size, the date and the name.
func BenchmarkPaintLine(b *testing.B) {
	const row = "drwxr-xr-x 2 root root 4096 Oct 06 12:00 /tmp/sub"
	spans := listingSpans(row)
	b.ReportAllocs()
	for b.Loop() {
		PaintLine(row, spans)
	}
}

// TestPaintLineOverlaysLaterSpans pins the stacking rule: a later span covers an
// earlier one on the stretch they share, and the parts outside it keep the base.
func TestPaintLineOverlaysLaterSpans(t *testing.T) {
	high := SeverityPaint(model.High)
	muted := MutedPaint()
	got := PaintLine("0123456789", []Span{
		{Start: 0, End: 10, Style: muted},
		{Start: 2, End: 4, Style: high},
	})
	if want := high.Style().Render("23"); !contains(got, want) {
		t.Fatalf("a later span should cover an earlier one: %q", plainText(got))
	}
	if want := muted.Style().Render("01"); !contains(got, want) {
		t.Fatalf("the leading part should keep the base color: %q", plainText(got))
	}
	if want := muted.Style().Render("456789"); !contains(got, want) {
		t.Fatalf("the trailing part should return to the base color: %q", plainText(got))
	}
	// Malformed spans paint nothing: an end before the start, and a range past
	// the line, both leave the text as it was.
	if got := PaintLine("abc", []Span{{Start: 2, End: 1, Style: high}}); got != "abc" {
		t.Fatalf("an empty range paints nothing: %q", got)
	}
	if got := PaintLine("abc", []Span{{Start: 0, End: 99, Style: muted}}); plainText(got) != "abc" {
		t.Fatalf("a range past the end keeps the text: %q", got)
	}
}
