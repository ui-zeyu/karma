// colon pseudo-lexer: colon-separated tables (passwd/group), fields cycled.

package syntax

import "strings"

// styleColonTable cycles colors through the fields of a colon-separated table
// (passwd/group); the last field keeps the default color.
func styleColonTable(line string) []paintSpan {
	fields := strings.Split(line, ":")
	if len(fields) < 2 {
		return nil
	}
	var spans []paintSpan
	offset := 0
	for index, field := range fields[:len(fields)-1] {
		spans = append(spans, paintSpan{
			Start: offset, End: offset + len(field),
			Style: tableColumnStyles[index%len(tableColumnStyles)],
		})
		offset += len(field) + 1
	}
	return spans
}
