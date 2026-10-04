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
	matched := findSubindex(brAddrRow, line)
	if matched == nil {
		return nil
	}
	spans := []Span{{Start: matched["iface"][0], End: matched["iface"][1], Style: style{fg: "4"}}}
	state := line[matched["state"][0]:matched["state"][1]]
	if st, ok := brStateStyles[state]; ok {
		spans = append(spans, Span{Start: matched["state"][0], End: matched["state"][1], Style: st})
	}
	return spans
}
