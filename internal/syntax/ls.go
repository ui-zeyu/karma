// ls -l pseudo-lexer: permissions, size, date, and the name colored by file
// kind (the shape script.LSBodyPrintf collects).

package syntax

import "strings"

var (
	lsTotal = compile(`^total \S+$`)
	// ls -l line shape: perms links owner group size date time path
	lsLine = compile(`^(?P<perms>[-dlbcps][rwxsStT-]{9}[.+]?)\s+\d+\s+\S+\s+\S+\s+` +
		`(?P<size>\S+)\s+(?P<date>[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{1,2}:\d{2}(?::\d{2})?|\d{4}))\s+` +
		`(?P<name>.+)$`)
)

func styleLsL(line string) []paintSpan {
	if lsTotal.MatchString(line) {
		return []paintSpan{{Start: 0, End: len(line), Style: mutedStyle}}
	}
	matched, ok := matchLine(lsLine, line)
	if !ok {
		return nil
	}
	permsStart, permsEnd, _ := matched.span("perms")
	sizeStart, sizeEnd, _ := matched.span("size")
	dateStart, dateEnd, _ := matched.span("date")
	nameAt, _, _ := matched.span("name")
	perms := line[permsStart:permsEnd]
	// The metadata is muted as a whole first, then lit up column by column
	spans := make([]paintSpan, 0, len(perms)+4)
	spans = append(spans, paintSpan{Start: 0, End: nameAt, Style: mutedStyle})
	spans = append(spans, permissionSpans(perms)...)
	spans = append(spans, paintSpan{Start: sizeStart, End: sizeEnd, Style: style{FG: "247"}})
	dateStyle := style{FG: "2"} // dark_green: with a time it is a recent change
	if !strings.Contains(line[dateStart:dateEnd], ":") {
		dateStyle = style{FG: "6"} // year only, cyan
	}
	spans = append(spans, paintSpan{Start: dateStart, End: dateEnd, Style: dateStyle})
	if kind, ok := lsKindStyle(perms); ok {
		spans = append(spans, paintSpan{Start: nameAt, End: len(line), Style: kind})
		if perms[0] == 'l' { // symlink: the arrow is dimmed, name and target share a color
			if arrow := strings.Index(line[nameAt:], " -> "); arrow >= 0 {
				spans = append(spans, paintSpan{Start: nameAt + arrow, End: nameAt + arrow + 4, Style: mutedStyle})
			}
		}
	}
	return spans
}

// permissionSpans paints the permission bits one by one; the first character is
// the type, and missing bits plus a trailing ACL indicator (. +) stay muted.
func permissionSpans(perms string) []paintSpan {
	spans := make([]paintSpan, 0, len(perms))
	for offset := range len(perms) {
		st, ok := lsFlagStyle(perms[offset])
		if offset == 0 {
			st, ok = lsTypeStyle(perms[offset])
		}
		if ok {
			spans = append(spans, paintSpan{Start: offset, End: offset + 1, Style: st})
		}
	}
	return spans
}

// Permission bits one by one; missing bits and a trailing ACL indicator (. +)
// stay muted
func lsFlagStyle(flag byte) (style, bool) {
	switch flag {
	case 'r':
		return style{FG: "2"}, true
	case 'w':
		return style{FG: "3"}, true
	case 'x':
		return style{FG: "1"}, true
	case 's', 'S', 't', 'T':
		return style{FG: "5", Bold: true}, true
	}
	return style{}, false
}

// The type character shares the name's color family (not bold); a regular
// file's - stays muted
func lsTypeStyle(flag byte) (style, bool) {
	switch flag {
	case 'd':
		return style{FG: "4"}, true
	case 'l':
		return style{FG: "6"}, true
	case 'b', 'c', 'p', 's':
		return style{FG: "5"}, true
	}
	return style{}, false
}

func lsKindStyle(perms string) (style, bool) {
	switch {
	case perms[0] == 'd':
		return style{FG: "4", Bold: true}, true
	case perms[0] == 'l':
		return style{FG: "6"}, true
	case strings.ContainsRune("bcps", rune(perms[0])) ||
		strings.ContainsAny(perms, "sS"):
		return style{FG: "5", Bold: true}, true
	case strings.Contains(perms, "x"):
		return style{FG: "2", Bold: true}, true
	}
	return style{}, false
}
