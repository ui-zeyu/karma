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
func styleReg(line string) []paintSpan {
	if strings.HasPrefix(line, "HKEY_") {
		return []paintSpan{{Start: 0, End: len(line), Style: style{fg: "4"}}}
	}
	if regContin.MatchString(line) {
		return []paintSpan{{Start: 0, End: len(line), Style: dimStyle}}
	}
	matched, ok := matchLine(regValueRow, line)
	if !ok {
		return nil
	}
	nameStart, nameEnd, _ := matched.span("name")
	typeStart, typeEnd, _ := matched.span("type")
	dataStart, dataEnd, _ := matched.span("data")
	spans := []paintSpan{
		{Start: nameStart, End: nameEnd, Style: style{fg: "4"}},
		{Start: typeStart, End: typeEnd, Style: keywordColor},
	}
	if regHexData.MatchString(line[dataStart:dataEnd]) {
		spans = append(spans, paintSpan{Start: dataStart, End: dataEnd, Style: dimStyle})
	}
	return spans
}
