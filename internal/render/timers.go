// timers pseudo-lexer: systemctl list-timers rows, whose date cells span
// several words ("Thu 2026-07-30 00:00:00 UTC"). The generic table styler
// colors word by word, so one date came out in four colors; this lexer reads
// the row as the six cells it is and paints each whole.

package render

import (
	"slices"
)

var (
	// A date cell: an optional weekday, the date, the time, an optional zone.
	// The token walk below assembles it; this only recognizes one word's part.
	timersTime = compile(`^\d{2}:\d{2}(?::\d{2})?$`)
	timersDate = compile(`^\d{4}-\d{2}-\d{2}$`)
	timersZone = compile(`^[A-Z]{2,5}$|^[+-]\d{2}:?\d{2}$`)
)

// timersRow paints one list-timers row: the two dates muted, the time left
// and the time passed in the reading colors, the unit and what it activates
// as the table's subject and action. A line that does not parse — the header,
// the closing count — carries no color.
func timersRow(line string) []paintSpan {
	tokens := slices.Collect(matches(historyWord, line))
	if len(tokens) < 6 {
		return nil
	}
	// From the right: ACTIVATES, UNIT.
	unit, activates := tokens[len(tokens)-2], tokens[len(tokens)-1]
	rest := tokens[:len(tokens)-2]
	pos := 0
	take := func(n int) (cell [2]int, ok bool) {
		if pos+n > len(rest) {
			return cell, false
		}
		cell = [2]int{rest[pos].start, rest[pos+n-1].end}
		pos += n
		return cell, true
	}
	// A date cell: "n/a", or weekday? date time zone?.
	dateCell := func() (cell [2]int, ok bool) {
		if rest[pos].text == "n/a" {
			return take(1)
		}
		n := 0
		if pos < len(rest) && !timersDate.MatchString(rest[pos].text) {
			n++ // the weekday
		}
		if pos+n >= len(rest) || !timersDate.MatchString(rest[pos+n].text) ||
			pos+n+1 >= len(rest) || !timersTime.MatchString(rest[pos+n+1].text) {
			return cell, false
		}
		n += 2
		if pos+n < len(rest) && timersZone.MatchString(rest[pos+n].text) {
			n++
		}
		return take(n)
	}
	// A delta cell: "n/a", or words ending in left/ago.
	deltaCell := func(word string) (cell [2]int, ok bool) {
		if rest[pos].text == "n/a" {
			return take(1)
		}
		n := 0
		for pos+n < len(rest) {
			if rest[pos+n].text == word {
				return take(n + 1)
			}
			n++
			if n > 3 {
				return cell, false
			}
		}
		return cell, false
	}
	next, ok := dateCell()
	if !ok {
		return nil
	}
	left, ok := deltaCell("left")
	if !ok {
		return nil
	}
	last, ok := dateCell()
	if !ok {
		return nil
	}
	passed, ok := deltaCell("ago")
	if !ok {
		return nil
	}
	if pos != len(rest) {
		return nil
	}
	var spans []paintSpan
	for _, cell := range [][2]int{next, last} {
		spans = append(spans, paintSpan{Start: cell[0], End: cell[1], Style: mutedStyle})
	}
	spans = append(spans,
		paintSpan{Start: left[0], End: left[1], Style: historyArgStyle},
		paintSpan{Start: passed[0], End: passed[1], Style: dimStyle},
		paintSpan{Start: unit.start, End: unit.end, Style: historySubjectStyle},
		paintSpan{Start: activates.start, End: activates.end, Style: historyActionStyle},
	)
	return spans
}
