// lsmod pseudo-lexer: module tables (lsmod and the /proc/modules fallback).

package render

import "slices"

// lsmodHeader is the header row of procps `lsmod`. The /proc/modules fallback
// tier has no header, and its data rows are colored straight by line shape.
var lsmodHeader = compile(`^Module\s+Size\s+Used by\b`)

// styleLsmod colors the kernel module table: module name, size, and reference
// count by column. The Used by tail (which may contain spaces) and the
// dependency and state fields of /proc/modules keep the default color; the
// header row is not painted.
func styleLsmod(line string) []paintSpan {
	if lsmodHeader.MatchString(line) {
		return nil
	}
	columns := slices.Collect(matches(wsColumn, line))
	if len(columns) < 3 {
		return nil
	}
	spans := make([]paintSpan, 0, 3)
	for i := range 3 {
		spans = append(spans, paintSpan{
			Start: columns[i].start, End: columns[i].end,
			Style: tableColumnStyles[i],
		})
	}
	return spans
}
