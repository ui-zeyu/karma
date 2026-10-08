// fstab pseudo-lexer: the six columns of a mount entry.

package render

// styleFstab colors an fstab row: device blue, mount point green, filesystem
// type magenta, options at the default color, and the dump and pass flags
// dimmed. Comment lines are left to the reader's comment muting.
func styleFstab(line string) []paintSpan {
	if line == "" || line[0] == '#' {
		return nil
	}
	var fields []word
	for field := range matches(wsColumn, line) {
		fields = append(fields, field)
	}
	if len(fields) < 4 { // device mount-point type options, dump and pass follow
		return nil
	}
	spans := []paintSpan{
		{Start: fields[0].start, End: fields[0].end, Style: style{FG: "4"}},
		{Start: fields[1].start, End: fields[1].end, Style: style{FG: "2"}},
		{Start: fields[2].start, End: fields[2].end, Style: style{FG: "5"}},
	}
	if len(fields) > 4 {
		spans = append(spans, paintSpan{Start: fields[4].start, End: fields[4].end, Style: dimStyle})
	}
	if len(fields) > 5 {
		spans = append(spans, paintSpan{Start: fields[5].start, End: fields[5].end, Style: dimStyle})
	}
	return spans
}
