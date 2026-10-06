// units pseudo-lexer: systemd unit tables (systemctl list-units) with the
// ACTIVE and SUB cells colored by meaning, plus the SysV fallback rows
// (`service --status-all`) the services check also collects.

package render

// unitStateStyles gives the state cells of a systemd unit table their meaning:
// alive (active/running) dark green, finished (exited/inactive) faint. failed
// keeps the cycling column color — it is a word, not a verdict; the rules
// decide what a row means.
var unitStateStyles = map[string]style{
	"active":   {fg: "2"},
	"running":  {fg: "2"},
	"exited":   dimStyle,
	"inactive": dimStyle,
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
	"+": {fg: "2"},
	"-": dimStyle,
	"?": dimStyle,
}

// sysvServiceSpans paints one `service --status-all` row: the marker as a
// single span in its state color, the name in the first table-column color —
// the same color the systemd table gives its UNIT column.
func sysvServiceSpans(line string) ([]Span, bool) {
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
	spans := []Span{{Start: markerStart, End: markerEnd, Style: state}}
	if nameStart, nameEnd, ok := matched.span("name"); ok {
		spans = append(spans, Span{Start: nameStart, End: nameEnd, Style: tableColumnStyles[0]})
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

func newUnitStyler() *unitStyler { return &unitStyler{table: newTableStyler(nil, true)} }

func (u *unitStyler) style(line string) []Span {
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
			spans = append(spans, Span{
				Start: column.start, End: column.end,
				Style: unitStateStyles[column.text],
			})
		}
	}
	return spans
}
