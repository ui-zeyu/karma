// fstab shaping: the six fields of a mount record padded to the body's own
// widest cell, so the panel reads the file as the table it is. Comments and
// blank lines keep their own bytes, and a record that is not six fields wide
// (a hand-edited, half-finished line) passes through untouched rather than
// being padded into a shape the file does not carry.

package shape

import (
	"fmt"
	"strings"

	"karma/internal/model"
)

// fstabFields is the record fstab(5) describes: spec, mount point, type,
// options, dump frequency, pass number.
const fstabFields = 6

// Fstab aligns an fstab body's records into columns. Both channels read the
// same file, so one shaping serves them both.
func Fstab(title, body string) *model.Shaped {
	split := lines(body)
	var widths [fstabFields]int
	type record struct {
		line   int
		fields []string
	}
	var records []record
	for i, line := range split {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != fstabFields {
			continue
		}
		for col, field := range fields {
			widths[col] = max(widths[col], len(field))
		}
		records = append(records, record{line: i, fields: fields})
	}
	if len(records) == 0 {
		return nil
	}
	var b strings.Builder
	next := 0
	for i, line := range split {
		if next < len(records) && records[next].line == i {
			fields := records[next].fields
			next++
			for col := 0; col < fstabFields-1; col++ {
				fmt.Fprintf(&b, "%-*s", widths[col]+columnGap, fields[col])
			}
			b.WriteString(fields[fstabFields-1])
		} else {
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}
	return shaped(b.String())
}
