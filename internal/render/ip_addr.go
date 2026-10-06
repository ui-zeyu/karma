// ip-addr pseudo-lexer: `ip -br addr` rows, the state colored by meaning.

package render

var brAddrRow = compile(`^(?P<iface>\S+)\s{2,}(?P<state>\S+)(?:\s{2,}(?P<rest>\S.*))?$`)

// ip -br addr columns are separated by 2+ spaces and an address cell has
// spaces inside (several addresses per interface); the state gets a semantic
// color
var brStateStyles = map[string]style{
	"UP":      {fg: "2"},
	"DOWN":    {faint: true},
	"UNKNOWN": {faint: true},
}

func styleIPAddr(line string) []Span {
	// ip -br addr rows are colored by column: interface blue, state by meaning,
	// the addresses themselves at the default color
	matched, ok := matchLine(brAddrRow, line)
	if !ok {
		return nil
	}
	ifaceStart, ifaceEnd, _ := matched.span("iface")
	stateStart, stateEnd, _ := matched.span("state")
	spans := []Span{{Start: ifaceStart, End: ifaceEnd, Style: style{fg: "4"}}}
	if st, ok := brStateStyles[line[stateStart:stateEnd]]; ok {
		spans = append(spans, Span{Start: stateStart, End: stateEnd, Style: st})
	}
	return spans
}
