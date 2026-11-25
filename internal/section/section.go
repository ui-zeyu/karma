// Package section owns the `== ` section header the built-in listing prints
// above each operand.
package section

import "strings"

// Marker opens a section header line.
const Marker = "== "

// Line renders the header line a report prints above a section's body, newline
// included.
func Line(title string) string { return Marker + title + "\n" }

// Title returns the title a header line opens; ok is false for a body line. The
// title is the rest of the line as it stands, trailing space included: a section
// title is what the producer wrote, and a reader that wants it trimmed says so.
func Title(line string) (string, bool) {
	title, ok := strings.CutPrefix(line, Marker)
	return title, ok
}
