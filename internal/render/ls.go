// ls -l pseudo-lexer: permissions, size, date, and the name colored by file
// kind (the shape script.LSBodyPrintf collects).

package render

import (
	"strings"

	"github.com/samber/lo"
)

var (
	lsTotal = compile(`^total \S+$`)
	// ls -l line shape: perms links owner group size date time path
	lsLine = compile(`^(?P<perms>[-dlbcps][rwxsStT-]{9}[.+]?)\s+\d+\s+\S+\s+\S+\s+` +
		`(?P<size>\S+)\s+(?P<date>[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{1,2}:\d{2}(?::\d{2})?|\d{4}))\s+` +
		`(?P<name>.+)$`)
)

func styleLsL(line string) []Span {
	if lsTotal.MatchString(line) {
		return []Span{{Start: 0, End: len(line), Style: mutedStyle}}
	}
	matched := findSubindex(lsLine, line)
	if matched == nil {
		return nil
	}
	perms := line[matched["perms"][0]:matched["perms"][1]]
	nameAt := matched["name"][0]
	// The metadata is muted as a whole first, then lit up column by column
	spans := []Span{{Start: 0, End: nameAt, Style: mutedStyle}}
	spans = append(spans, permissionSpans(perms)...)
	spans = append(spans, Span{Start: matched["size"][0], End: matched["size"][1], Style: style{fg: "247"}})
	dateStyle := style{fg: "2"} // dark_green: with a time it is a recent change
	if !strings.Contains(line[matched["date"][0]:matched["date"][1]], ":") {
		dateStyle = style{fg: "6"} // year only, cyan
	}
	spans = append(spans, Span{Start: matched["date"][0], End: matched["date"][1], Style: dateStyle})
	if kind, ok := lsKindStyle(perms); ok {
		spans = append(spans, Span{Start: nameAt, End: len(line), Style: kind})
		if perms[0] == 'l' { // symlink: the arrow is dimmed, name and target share a color
			if arrow := strings.Index(line[nameAt:], " -> "); arrow >= 0 {
				spans = append(spans, Span{Start: nameAt + arrow, End: nameAt + arrow + 4, Style: mutedStyle})
			}
		}
	}
	return spans
}

// permissionSpans paints the permission bits one by one; the first character is
// the type, and missing bits plus a trailing ACL indicator (. +) stay muted.
func permissionSpans(perms string) []Span {
	return lo.FilterMap([]byte(perms), func(flag byte, offset int) (Span, bool) {
		st, ok := lsFlagStyle(flag)
		if offset == 0 {
			st, ok = lsTypeStyle(flag)
		}
		if !ok {
			return Span{}, false
		}
		return Span{Start: offset, End: offset + 1, Style: st}, true
	})
}

// Permission bits one by one; missing bits and a trailing ACL indicator (. +)
// stay muted
func lsFlagStyle(flag byte) (style, bool) {
	switch flag {
	case 'r':
		return style{fg: "2"}, true
	case 'w':
		return style{fg: "3"}, true
	case 'x':
		return style{fg: "1"}, true
	case 's', 'S', 't', 'T':
		return style{fg: "5", bold: true}, true
	}
	return style{}, false
}

// The type character shares the name's color family (not bold); a regular
// file's - stays muted
func lsTypeStyle(flag byte) (style, bool) {
	switch flag {
	case 'd':
		return style{fg: "4"}, true
	case 'l':
		return style{fg: "6"}, true
	case 'b', 'c', 'p', 's':
		return style{fg: "5"}, true
	}
	return style{}, false
}

func lsKindStyle(perms string) (style, bool) {
	switch {
	case perms[0] == 'd':
		return style{fg: "4", bold: true}, true
	case perms[0] == 'l':
		return style{fg: "6"}, true
	case strings.ContainsRune("bcps", rune(perms[0])) ||
		strings.ContainsAny(perms, "sS"):
		return style{fg: "5", bold: true}, true
	case strings.Contains(perms, "x"):
		return style{fg: "2", bold: true}, true
	}
	return style{}, false
}
