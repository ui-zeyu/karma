// Home-tree shaping: the listing rows both fallbacks print (the in-process walk
// and the remote find) become the drawing tree(1) makes of the same walk —
// branch glyphs, one row per entry, each carrying the attributes tree's -pugsD
// flags print and the entry's whole path. A body tree already drew (the target
// has tree installed) is passed through untouched.

package shape

import (
	"fmt"
	"regexp"
	"strings"

	"karma/internal/model"
)

// homeTreeRow matches one listing row in script.LSBodyPrintf's shape: mode,
// link count, user, group, size, the three words of find's date (month, day,
// time), then the path — which may hold blanks, and a symlink's " -> target"
// tail. tree prints no link count, so the label drawn drops that field.
var homeTreeRow = regexp.MustCompile(`^(\S+) \d+ (\S+) (\S+) (\d+) (\S+) (\S+) (\S+) (.+)$`)

// HomeTree draws the walk's rows as a tree. Every row must parse; one that
// does not declines the whole body, so nothing but the walk's own output is
// redrawn.
func HomeTree(title, body string) *model.Shaped {
	if strings.ContainsAny(body, "├└") {
		return nil
	}
	tree := NewTree()
	for _, line := range lines(body) {
		match := homeTreeRow.FindStringSubmatch(line)
		if match == nil {
			return nil
		}
		// The row's path field is the whole path with the symlink's target
		// after it; the tree position is the path alone, and the label keeps
		// the target the row carried. match[2] is the link count, the one
		// field tree's flags do not print.
		display := match[8]
		path, _, _ := strings.Cut(display, " -> ")
		label := fmt.Sprintf("[%s %s %s %s %s %s %s]  %s",
			match[1], match[2], match[3], match[4], match[5], match[6], match[7], display)
		tree.Add(path, label, strings.HasPrefix(match[1], "d"))
	}
	if tree.Empty() {
		return nil
	}
	return shaped(tree.String())
}
