// The built-in reader's listing colors: the heuristic the old listing wore —
// permissions by meaning, the size grey, a fresh date green and an old one
// cyan, the name by file kind. Rows that are not ls -l bodies pass through.

package cli

import (
	"regexp"
	"strings"

	chrome "karma/internal/panel"
)

// lsRowPattern is the reader's ls -l body row: permissions, links, owner,
// group, size, date, the name and (for a symlink) its arrow and target.
var lsRowPattern = regexp.MustCompile(
	`^(?P<perms>[-dlbcps][rwxsStT-]{9}[.+]?)\s+\d+\s+\S+\s+\S+\s+(?P<size>\S+)\s+` +
		`(?P<date>[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{1,2}:\d{2}(?::\d{2})?|\d{4}))\s+(?P<name>.+)$`)

// lsRow paints one listing row; color off returns it untouched.
func lsRow(color bool, row string) string {
	if !color {
		return row
	}
	match := lsRowPattern.FindStringSubmatchIndex(row)
	if match == nil {
		return row
	}
	perms := row[match[2]:match[3]]
	size := row[match[4]:match[5]]
	date := row[match[6]:match[7]]
	name := row[match[8]:match[9]]
	var out strings.Builder
	for index := 0; index < len(perms); index++ {
		if code, bold, ok := lsBitHue(perms[index], index == 0); ok {
			out.WriteString(paintCode(code, bold, perms[index:index+1]))
			continue
		}
		out.WriteByte(perms[index])
	}
	muted := chrome.Paint(true, chrome.Fg(chrome.MutedColor), row[len(perms):match[4]])
	out.WriteString(muted)
	out.WriteString(chrome.Paint(true, chrome.Fg(247), size))
	out.WriteString(chrome.Paint(true, chrome.Fg(chrome.MutedColor), row[match[5]:match[6]]))
	out.WriteString(chrome.Paint(true, chrome.Fg(lsDateHue(date)), date))
	out.WriteString(chrome.Paint(true, chrome.Fg(chrome.MutedColor), row[match[7]:match[8]]))
	if perms[0] == 'l' {
		if arrow := strings.Index(name, " -> "); arrow >= 0 {
			out.WriteString(paintCode(6, false, name[:arrow]))
			out.WriteString(chrome.Paint(true, chrome.Fg(chrome.MutedColor), name[arrow:arrow+4]))
			out.WriteString(paintCode(6, false, name[arrow+4:]))
			return out.String()
		}
	}
	if code, bold, ok := lsKindHue(perms); ok {
		out.WriteString(paintCode(code, bold, name))
		return out.String()
	}
	out.WriteString(name)
	return out.String()
}

// lsDateHue: a date that carries a clock is a recent change (green); a year
// is old (cyan).
func lsDateHue(date string) int {
	if strings.Contains(date, ":") {
		return 2
	}
	return 6
}

// lsBitHue paints one permission character; the first character is the file
// type, the rest are the permission bits.
func lsBitHue(bit byte, first bool) (int, bool, bool) {
	if first {
		switch bit {
		case 'd':
			return 4, false, true
		case 'l':
			return 6, false, true
		case 'b', 'c', 'p', 's':
			return 5, false, true
		}
		return 0, false, false
	}
	switch bit {
	case 'r':
		return 2, false, true
	case 'w':
		return 3, false, true
	case 'x':
		return 1, false, true
	case 's', 'S', 't', 'T':
		return 5, true, true
	}
	return 0, false, false
}

// lsKindHue colors the name by file kind: a directory blue, a symlink cyan,
// a device or socket magenta, an executable green.
func lsKindHue(perms string) (int, bool, bool) {
	switch {
	case perms[0] == 'd':
		return 4, true, true
	case perms[0] == 'l':
		return 6, false, true
	case strings.ContainsRune("bcps", rune(perms[0])) || strings.ContainsAny(perms, "sS"):
		return 5, true, true
	case strings.Contains(perms, "x"):
		return 2, true, true
	}
	return 0, false, false
}

// paintCode paints text in one 256-color hue, optionally bold.
func paintCode(code int, bold bool, text string) string {
	codes := chrome.Fg(code)
	if bold {
		codes += "\x1b[1m"
	}
	return chrome.Paint(true, codes, text)
}
