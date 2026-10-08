// last pseudo-lexer: last(1)'s rows — and lastb's, which are the same table.
//
// The row is four cells: the account, the terminal, the host, and the login
// time. The time's own spelling carries the blank that a word-by-word pass
// cannot see — last pads the day to two cells ("Thu Oct  8 07:14"), so one
// login came out in four colors — and the cells are read here instead. A boot
// record's terminal is two words in one cell ("system boot", "system down"),
// which last itself prints that way. The words after the time — the logout, the
// session's length, and last's own closing words ("still logged in",
// "gone - no logout") — stay plain, the way a table's last column does.

package syntax

import (
	"slices"
)

var (
	// lastWeekday, lastMonth, lastDay and lastClock are the login time's own
	// tokens, in the C locale last prints them in.
	lastWeekday = compile(`^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)$`)
	lastMonth   = compile(`^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$`)
	lastDay     = compile(`^\d{1,2}$`)
	lastClock   = compile(`^\d{2}:\d{2}(?::\d{2})?$`)
)

// lastTimeColumn is the time cell's column: last pads the three cells ahead of
// it (8, 12 and 16 cells), so the time takes the fourth column's color on every
// row — a console login, whose host cell is empty, included.
const lastTimeColumn = 3

// styleLast paints one last(1) row: the account, the terminal, the host and the
// login time in the table's first four column colors, in the order the row
// prints them.
func styleLast(line string) []paintSpan {
	if logTrailer.MatchString(line) {
		return nil
	}
	tokens := slices.Collect(matches(wsColumn, line))
	when, ok := lastTime(tokens)
	if !ok {
		return nil
	}
	var spans []paintSpan
	for index, cell := range lastCells(tokens[:when[0]]) {
		for _, token := range cell {
			spans = append(spans, paintSpan{Start: token.start, End: token.end,
				Style: tableColumnStyles[index%len(tableColumnStyles)]})
		}
	}
	for _, token := range tokens[when[0]:when[1]] {
		spans = append(spans, paintSpan{Start: token.start, End: token.end,
			Style: tableColumnStyles[lastTimeColumn]})
	}
	return spans
}

// lastTime locates the login time's tokens among a row's: the first weekday
// followed by a month, the day and the clock. Its two indices are the cell's
// first and last token. A row with no such cell — the trailer naming where the
// records begin is one — carries no color.
func lastTime(tokens []word) ([2]int, bool) {
	for index := 0; index+4 <= len(tokens); index++ {
		if !lastWeekday.MatchString(tokens[index].text) || !lastMonth.MatchString(tokens[index+1].text) ||
			!lastDay.MatchString(tokens[index+2].text) || !lastClock.MatchString(tokens[index+3].text) {
			continue
		}
		return [2]int{index, index + 4}, true
	}
	return [2]int{}, false
}

// lastCells groups the words ahead of the login time into the cells the row
// prints: the account, the terminal and the host. The terminal is two words on
// a boot record, where last prints "system boot" or "system down" in the one
// cell, and the host carries whatever is left — the kernel a boot record names
// there, and nothing at all for a console login, whose host cell is blank.
func lastCells(tokens []word) [][]word {
	if len(tokens) == 0 {
		return nil
	}
	cells := [][]word{tokens[:1]}
	rest := tokens[1:]
	if len(rest) >= 2 && rest[0].text == "system" && (rest[1].text == "boot" || rest[1].text == "down") {
		cells = append(cells, rest[:2])
		rest = rest[2:]
	} else if len(rest) > 0 {
		cells = append(cells, rest[:1])
		rest = rest[1:]
	}
	if len(rest) > 0 {
		cells = append(cells, rest)
	}
	return cells
}
