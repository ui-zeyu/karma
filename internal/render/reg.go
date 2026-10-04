// reg pseudo-lexer: Windows reg.exe query dumps (key paths, value rows).

package render

import "strings"

var (
	// reg.exe value rows: 4-space indent, 4+ spaces between columns (the same
	// shape checks/windows/regutil parses)
	regValueRow = compile(`^(?P<indent>\s+)(?P<name>\S.*?)\s{4}(?P<type>REG_[A-Z]+)\s+(?P<data>.*)$`)
	regHexData  = compile(`^(?:0x[0-9A-Fa-f]+\b|[0-9A-Fa-f]{2}(?:,[0-9A-Fa-f]{2})+)`)
	regContin   = compile(`^ {8,}\S`)
)

// styleReg colors a reg query dump: the key path whole-line blue, a value row's
// name blue, its type dark magenta, and hex data dimmed, with other data at the
// default color.
func styleReg(line string) []Span {
	if strings.HasPrefix(line, "HKEY_") {
		return []Span{{Start: 0, End: len(line), Style: style{fg: "4"}}}
	}
	if regContin.MatchString(line) {
		return []Span{{Start: 0, End: len(line), Style: dimStyle}}
	}
	matched := findSubindex(regValueRow, line)
	if matched == nil {
		return nil
	}
	spans := []Span{
		{Start: matched["name"][0], End: matched["name"][1], Style: style{fg: "4"}},
		{Start: matched["type"][0], End: matched["type"][1], Style: keywordColor},
	}
	if regHexData.MatchString(line[matched["data"][0]:matched["data"][1]]) {
		spans = append(spans, Span{Start: matched["data"][0], End: matched["data"][1], Style: dimStyle})
	}
	return spans
}
