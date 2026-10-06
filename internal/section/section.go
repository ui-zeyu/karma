// Package section owns the `== ` section convention of collected text: the one
// marker line that opens a section, and the split that turns a text into
// sections. The collection scripts, the in-process tiers and the readers of an
// incoming collection all speak it, so the marker and the split live here rather
// than once per producer and once per reader.
//
// The convention is line-based. A line that starts with `== ` opens a section and
// names it; every line after it belongs to that section until the next marker.
// Text before the first marker is the preamble — a section with no title, which
// is where the output of a single command with no marker of its own lands.
//
// The marker is spliced from Marker wherever the text is built in Go. The shell,
// awk and PowerShell programs the catalog carries spell `== ` as source of their
// own language, and the tests that run those programs against a fixture are what
// keeps them in step with this one.
package section

import (
	"iter"
	"strings"

	"karma/internal/textutil"
)

// Marker opens a section line. It is the whole protocol: the emitters print it,
// Title reads it, and a reader of collected text never sees any other spelling.
const Marker = "== "

// Line renders the marker line an emitter prints for a title, newline included.
// A Go emitter that prints a title uses this; one that builds its own shell, awk
// or PowerShell text splices Marker where its language needs it.
func Line(title string) string { return Marker + title + "\n" }

// Title returns the title a line opens; ok is false for a body line. The title is
// the rest of the line as it stands, trailing space included: a section title is
// what the producer wrote, and a reader that wants it trimmed says so.
func Title(line string) (string, bool) {
	title, ok := strings.CutPrefix(line, Marker)
	return title, ok
}

// Section is one section of collected text: the title its marker named, whether
// it had one (Marked is false for the preamble), and the lines that followed.
type Section struct {
	Title  string
	Marked bool
	Lines  []string
}

// Parse cuts text into sections, lazily: one Section at a time, so a reader holds
// no more than the section it is shaping. The line splitting is textutil.Lines'
// (a lone CR breaks a line as well, and a trailing empty line is not a line),
// which is what every reader of collected text used before this package.
func Parse(text string) iter.Seq[Section] {
	return func(yield func(Section) bool) {
		var current Section
		started := false
		for line := range textutil.Lines(text) {
			if title, ok := Title(line); ok {
				if started && !yield(current) {
					return
				}
				current, started = Section{Title: title, Marked: true}, true
				continue
			}
			current.Lines = append(current.Lines, line)
			started = true
		}
		if started {
			yield(current)
		}
	}
}
