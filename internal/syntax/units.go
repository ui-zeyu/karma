// units pseudo-lexer: systemd unit tables (systemctl list-units) with the
// ACTIVE and SUB cells colored by meaning, the unit-file listing
// (list-unit-files) with its state words colored by value, plus the SysV
// fallback rows (`service --status-all`) the services check also collects.

package syntax

import "slices"

// unitStateStyles gives the state cells of a systemd unit table their meaning:
// alive (active/running) dark green, finished (exited/inactive) faint, dead
// dark yellow — a unit the manager gave up on reads apart from both. failed
// keeps the cycling column color — it is a word, not a verdict; the rules
// decide what a row means.
var unitStateStyles = map[string]style{
	"active":   {FG: "2"},
	"running":  {FG: "2"},
	"exited":   dimStyle,
	"inactive": dimStyle,
	"dead":     {FG: "3"},
}

// sysvServiceLine matches one `service --status-all` row: the bracketed state
// marker and the service name. The marker is one field, so it takes one span;
// left to the table's word-by-word cycle the bracket, the sign, and the closing
// bracket came out in three different colors.
var sysvServiceLine = compile(`^\s*(?P<marker>\[\s*(?P<sign>[+?-])\s*\])(?P<gap>\s+)(?P<name>\S+)`)

// sysvServiceStyles gives the marker its meaning in the same language as
// unitStateStyles: `+` (running) dark green, `-` and `?` (stopped, unknown)
// faint.
var sysvServiceStyles = map[string]style{
	"+": {FG: "2"},
	"-": dimStyle,
	"?": dimStyle,
}

// sysvServiceSpans paints one `service --status-all` row: the marker as a
// single span in its state color, the name in the first table-column color —
// the same color the systemd table gives its UNIT column.
func sysvServiceSpans(line string) ([]paintSpan, bool) {
	matched, ok := matchLine(sysvServiceLine, line)
	if !ok {
		return nil, false
	}
	markerStart, markerEnd, ok := matched.span("marker")
	if !ok {
		return nil, false
	}
	signStart, signEnd, _ := matched.span("sign")
	state, ok := sysvServiceStyles[line[signStart:signEnd]]
	if !ok {
		return nil, false
	}
	spans := []paintSpan{{Start: markerStart, End: markerEnd, Style: state}}
	if nameStart, nameEnd, ok := matched.span("name"); ok {
		spans = append(spans, paintSpan{Start: nameStart, End: nameEnd, Style: tableColumnStyles[0]})
	}
	return spans, true
}

// unitStyler colors systemd unit tables (`systemctl list-units`) and the SysV
// service listing collected with them: columns as elsewhere, then the ACTIVE
// and SUB cells repainted by meaning. Restricting the repaint to those two
// anchored columns keeps a state word in the DESCRIPTION column at the plain
// table color.
type unitStyler struct {
	table *tableStyler
}

func newUnitStyler() *unitStyler { return &unitStyler{table: newTableStyler(nil)} }

func (u *unitStyler) style(line string) []paintSpan {
	if spans, ok := sysvServiceSpans(line); ok {
		return spans
	}
	spans := u.table.style(line)
	if len(u.table.starts) < 4 { // UNIT LOAD ACTIVE SUB
		return spans
	}
	for column := range matches(wsColumn, line) {
		if _, ok := unitStateStyles[column.text]; !ok {
			continue
		}
		switch pos := columnIndex(u.table.starts, column.start); pos {
		case 2, 3:
			spans = append(spans, paintSpan{
				Start: column.start, End: column.end,
				Style: unitStateStyles[column.text],
			})
		}
	}
	return spans
}

// unitFileStateStyles paints the words a `systemctl list-unit-files` row
// carries after the name — the unit's own state and the vendor preset — by
// their value: enabled dark green, everything the preset would not turn on
// faint. A row then reads at a glance which units boot and which were talked
// out of it.
var unitFileStateStyles = map[string]style{
	"enabled":   {FG: "2"},
	"disabled":  dimStyle,
	"masked":    dimStyle,
	"static":    dimStyle,
	"indirect":  dimStyle,
	"generated": dimStyle,
	"transient": dimStyle,
}

// styleUnitFiles colors one list-unit-files row: the unit name in the first
// table-column color, every state word by its value.
func styleUnitFiles(line string) []paintSpan {
	tokens := slices.Collect(matches(historyWord, line))
	if len(tokens) < 2 {
		return nil
	}
	spans := []paintSpan{{
		Start: tokens[0].start, End: tokens[0].end,
		Style: tableColumnStyles[0],
	}}
	for _, token := range tokens[1:] {
		if state, ok := unitFileStateStyles[token.text]; ok {
			spans = append(spans, paintSpan{Start: token.start, End: token.end, Style: state})
		}
	}
	return spans
}
