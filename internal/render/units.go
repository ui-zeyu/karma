// units pseudo-lexer: systemd unit tables (systemctl list-units) with the
// ACTIVE and SUB cells colored by meaning.

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

// unitStyler colors systemd unit tables (`systemctl list-units`): columns as
// elsewhere, then the ACTIVE and SUB cells repainted by meaning. Restricting
// the repaint to those two anchored columns keeps a state word in the
// DESCRIPTION column at the plain table color.
type unitStyler struct {
	table *tableStyler
}

func newUnitStyler() *unitStyler { return &unitStyler{table: newTableStyler(nil, true)} }

func (u *unitStyler) style(line string) []Span {
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
