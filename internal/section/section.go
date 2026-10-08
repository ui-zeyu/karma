// Package section owns the `== ` section header of the report: the one line the
// report shows above a section's body, and the only spelling it uses for one.
//
// The header is presentation, never a boundary: sections arrive named from the
// collection (model.BodySection), so no byte a tier read — a file's contents, a
// tool's output, a path in a listing — can become a section. The readers here
// exist for the places that state a body as text: the evidence the report keeps
// (reader.Evidence) and the built-in readers whose output is the text itself.
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
