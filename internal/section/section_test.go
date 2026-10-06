package section

import (
	"slices"
	"strings"
	"testing"
)

// collect drains the iterator, so a test can compare sections as values.
func collect(text string) []Section {
	return slices.Collect(Parse(text))
}

// The split is the protocol: a marker opens a section and the lines after it
// belong to it, including the blank ones, which the reader counts like any other.
func TestParseSplitsOnTheMarker(t *testing.T) {
	got := collect("== one\nalpha\n\nbeta\n== two\ngamma\n")
	want := []Section{
		{Title: "one", Marked: true, Lines: []string{"alpha", "", "beta"}},
		{Title: "two", Marked: true, Lines: []string{"gamma"}},
	}
	if !slices.EqualFunc(got, want, sameSection) {
		t.Errorf("Parse = %+v, want %+v", got, want)
	}
}

// Text before the first marker is the preamble: one section, no title. It is
// where a command's output with no marker of its own lands.
func TestParseKeepsThePreambleUntitled(t *testing.T) {
	got := collect("stray line\n== one\nalpha\n")
	if len(got) != 2 {
		t.Fatalf("Parse = %+v, want the preamble and one section", got)
	}
	if got[0].Title != "" || got[0].Marked || !slices.Equal(got[0].Lines, []string{"stray line"}) {
		t.Errorf("the preamble came back as %+v", got[0])
	}
	if got[1].Title != "one" || !got[1].Marked {
		t.Errorf("the titled section came back as %+v", got[1])
	}
}

// A marker with nothing under it is still a section: a producer that prints the
// title of a source it could not read leaves an empty section behind, and the
// reading layer decides what to do with it.
func TestParseKeepsATitleWithNoBody(t *testing.T) {
	got := collect("== one\n== two\nalpha\n")
	if len(got) != 2 || got[0].Title != "one" || len(got[0].Lines) != 0 {
		t.Fatalf("Parse = %+v, want an empty section first", got)
	}
}

// Empty text has no sections at all, so a quiet check renders nothing rather
// than an empty box.
func TestParseOfEmptyTextIsNoSections(t *testing.T) {
	if got := collect(""); len(got) != 0 {
		t.Errorf("Parse of empty text = %+v, want nothing", got)
	}
	if got := collect("== "); len(got) != 1 || got[0].Title != "" {
		t.Errorf("Parse of a bare marker = %+v, want one untitled section", got)
	}
}

// The title is the rest of the line as it stands, and a body line that merely
// looks like a marker in another position is not one.
func TestTitleReadsOnlyALeadingMarker(t *testing.T) {
	if title, ok := Title("== sshd_config"); !ok || title != "sshd_config" {
		t.Errorf("Title = %q, %v", title, ok)
	}
	if title, ok := Title("== trailing  "); !ok || title != "trailing  " {
		t.Errorf("Title trims what the producer wrote: %q", title)
	}
	if _, ok := Title("a == b"); ok {
		t.Error("a marker in the middle of a line opens nothing")
	}
	if _, ok := Title("==one"); ok {
		t.Error("a marker needs its space")
	}
}

// Line is the emitter's half: the text a Go emitter prints for a title is the
// text Parse reads back as that title, newline included.
func TestLineRoundTripsThroughParse(t *testing.T) {
	got := collect(Line("kernel/module-memory") + "body\n")
	want := []Section{{Title: "kernel/module-memory", Marked: true, Lines: []string{"body"}}}
	if !slices.EqualFunc(got, want, sameSection) {
		t.Errorf("Line then Parse = %+v, want %+v", got, want)
	}
	if !strings.HasPrefix(Line("x"), Marker) {
		t.Errorf("Line should start with the marker, got %q", Line("x"))
	}
}

func sameSection(a, b Section) bool {
	return a.Title == b.Title && a.Marked == b.Marked && slices.Equal(a.Lines, b.Lines)
}
