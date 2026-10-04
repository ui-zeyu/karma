// ip-keyval pseudo-lexer: key/value rows of ip route / ip neigh, with the
// table headers of `ip route show` falling through to column colors.

package render

import (
	"regexp"
	"slices"
)

var (
	// Key/value rows of ip route / ip neigh: the destination is lit, keys get
	// dark magenta, and a trailing all-caps word is a neighbor state
	// (REACHABLE/STALE…), which gets cyan
	keyvalKeys = compile(`\b(?:via|dev|proto|scope|src|metric|table|mtu|weight|onlink|lladdr|nud` +
		`|expires|offload)\b`)
	keyvalDest = compile(`^(?:default|blackhole|unreachable|prohibit|throw` +
		`|(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?` +
		`|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})`)
	routeTableHeader = compile(`^Destination\s+Gateway\s`)
	arpTableHeader   = compile(`^Address\s+HWtype\s`)
)

// keyvalStyler colors the key/value rows of ip route / ip neigh; header rows are
// anchored and then given column colors by interval.
type keyvalStyler struct {
	table *tableStyler
}

func newKeyvalStyler() *keyvalStyler {
	// cycle off: preamble lines such as netstat's "Kernel IP routing table" are
	// not table data and stay plain until the anchor is set
	return &keyvalStyler{table: newTableStyler([]*regexp.Regexp{routeTableHeader, arpTableHeader}, false)}
}

func (k *keyvalStyler) style(line string) []Span {
	columns := slices.Collect(matches(wsColumn, line))
	if len(columns) < 2 {
		return nil
	}
	first, last := columns[0], columns[len(columns)-1]
	if keyvalKeys.MatchString(line) && keyvalDest.MatchString(first.text) {
		spans := []Span{{Start: first.start, End: first.end, Style: style{fg: "4"}}}
		for key := range matches(keyvalKeys, line) {
			spans = append(spans, Span{Start: key.start, End: key.end, Style: style{fg: "5"}})
		}
		if wholeToken(headerToken, last.text) {
			spans = append(spans, Span{Start: last.start, End: last.end, Style: style{fg: "6"}})
		}
		return spans
	}
	return k.table.style(line)
}
