// pipe pseudo-lexer: ` | `-segmented rows (usb-devices, software).

package syntax

import "strings"

var (
	pipeLabel = compile(`Installed|Last Connected|Last Removed`)
	pipeTime  = compile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)
)

// stylePipeTable handles ` | `-segmented rows (usb-devices' "name | instance |
// label time" and software's "name | version | date"): the first segment blue,
// the second dimmed, known labels muted, times green, and the separators muted.
func stylePipeTable(line string) []paintSpan {
	segments := strings.Split(line, " | ")
	if len(segments) < 2 {
		return nil
	}
	var spans []paintSpan
	offset := 0
	for index, segment := range segments {
		switch index {
		case 0:
			spans = append(spans, paintSpan{Start: offset, End: offset + len(segment), Style: style{FG: "4"}})
		case 1:
			spans = append(spans, paintSpan{Start: offset, End: offset + len(segment), Style: dimStyle})
		default:
			for _, loc := range pipeLabel.FindAllStringIndex(segment, -1) {
				spans = append(spans, paintSpan{Start: offset + loc[0], End: offset + loc[1], Style: mutedStyle})
			}
			for _, loc := range pipeTime.FindAllStringIndex(segment, -1) {
				spans = append(spans, paintSpan{Start: offset + loc[0], End: offset + loc[1], Style: style{FG: "2"}})
			}
		}
		if index < len(segments)-1 {
			sep := offset + len(segment)
			spans = append(spans, paintSpan{Start: sep, End: sep + 3, Style: mutedStyle})
		}
		offset += len(segment) + 3
	}
	return spans
}
