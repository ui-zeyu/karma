// Package section owns the `== ` section header the built-in listing prints
// above each operand.
package section

// Marker opens a section header line.
const Marker = "== "

// Line renders the header line a report prints above a section's body, newline
// included.
func Line(title string) string { return Marker + title + "\n" }
