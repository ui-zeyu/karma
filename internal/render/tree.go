// tree pseudo-lexer: the drawn tree's branch lead colored by nesting, and
// tree's own closing count muted. The label a branch carries is left for the
// hits — a colored skeleton is the level's business, and a finding on a node
// still reads as the loudest thing on its line.

package render

import (
	"strings"

	"karma/internal/form"
)

// The branch lead's segments, spelled here as the collected text carries
// them: a bar carries its level's line down, a gap is where a closed branch
// sat, and the glyph opens the node's own level. They are tree(1)'s glyphs,
// the same ones form.Tree and shape.Tree draw.
const (
	treeBar = "│   "
	treeGap = "    "
	treeMid = "├── "
	treeEnd = "└── "
)

// treeCount is tree's own closing line: "3 directories, 4 files".
var treeCount = compile(`^\d+ director(?:y|ies), \d+ files?$`)

// styleTree colors a drawn tree's lead by nesting: each bar takes the hue of
// the level it descends from and the branch glyph the node's own. A line whose
// lead is none of these — a root's label, a body another tool wrote, the ASCII
// branches a non-UTF-8 locale makes tree print — is not this lexer's and stays
// plain.
func styleTree(line string) []paintSpan {
	if treeCount.MatchString(line) {
		return []paintSpan{{Start: 0, End: len(line), Style: mutedStyle}}
	}
	var spans []paintSpan
	at, level := 0, 1
	for {
		switch {
		case strings.HasPrefix(line[at:], treeBar):
			spans = append(spans, paintSpan{Start: at, End: at + len(treeBar), Style: form.LevelPaint(level)})
			at += len(treeBar)
		case strings.HasPrefix(line[at:], treeGap):
			at += len(treeGap)
		case strings.HasPrefix(line[at:], treeMid), strings.HasPrefix(line[at:], treeEnd):
			spans = append(spans, paintSpan{Start: at, End: at + len(treeMid), Style: form.LevelPaint(level)})
			return spans
		default:
			return nil
		}
		level++
	}
}
