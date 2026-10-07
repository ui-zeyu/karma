package form

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"karma/internal/model"
)

// The branch glyphs are tree(1)'s own, so a nest karma draws reads like the one
// the tool draws.
const (
	branchMid = "├── "
	branchEnd = "└── "
	branchBar = "│   "
	branchGap = "    "
)

// Tree draws records as a nest: one node per line, one level deeper than its
// parent, with tree(1)'s branch glyphs and the hits the rules located painted
// on the node they were judged on.
//
// The nest is this form's own work, so a check states what a node is — its
// identity, its parent, the columns to draw — and never how deep to indent it.
// A node whose parent the block does not hold starts a root, which is also what
// a parent the display budget hid leaves behind: a tree never draws a node
// under one it cannot see.
type Tree struct {
	// ID names the column that identifies a node. Siblings follow it in
	// numeric order when every one of them is a number, and in byte order
	// otherwise, so a nest draws the same way on every run.
	ID string
	// Parent names the column that holds a node's parent identity.
	Parent string
	// Label names the columns drawn on a node's line, in order; an empty value
	// is dropped, so a node the target spelled no command line for draws its
	// identity alone.
	Label []string
}

// Render draws the nest: every root in order, its subtree under it, and the
// caller's structural notes after them — a note counts the rows the display
// budget hid, and the nest has no place among the branches to put one.
func (t Tree) Render(block model.Block, opts model.RenderOptions) []string {
	kids, roots := t.nest(block)
	var rows []string
	seen := make([]bool, len(block.Items))
	var draw func(at int, prefix string, branch, last bool)
	draw = func(at int, prefix string, branch, last bool) {
		seen[at] = true
		glyph, below := "", prefix
		if branch {
			glyph, below = branchMid, prefix+branchBar
			if last {
				glyph, below = branchEnd, prefix+branchGap
			}
		}
		rows = append(rows, t.row(block.Items[at], prefix+glyph, opts)...)
		siblings := kids[at]
		final := -1
		for _, kid := range siblings {
			if !seen[kid] {
				final = kid
			}
		}
		for _, kid := range siblings {
			if seen[kid] {
				continue
			}
			// The last sibling still to be drawn closes the branch, whether or
			// not every one of them is drawn.
			draw(kid, below, true, kid == final)
		}
	}
	for _, root := range roots {
		draw(root, "", false, false)
	}
	// A body whose parent links close a cycle reaches no root; drawing what is
	// left keeps the form total instead of dropping those nodes.
	for at := range block.Items {
		if !seen[at] && block.Items[at].Rec != nil {
			draw(at, "", false, false)
		}
	}
	for _, item := range block.Items {
		if item.Rec == nil && item.Note != "" {
			rows = append(rows, noteRow(item.Note, opts))
		}
	}
	return rows
}

// nest works the tree out of the parent links: each node's children, and the
// roots — the nodes whose parent the block does not hold, its own included.
func (t Tree) nest(block model.Block) (map[int][]int, []int) {
	byID := make(map[string]int, len(block.Items))
	for at, item := range block.Items {
		if item.Rec == nil {
			continue
		}
		if id, ok := item.Rec.Value(t.ID); ok && id != "" {
			byID[id] = at
		}
	}
	kids := make(map[int][]int, len(byID))
	var roots []int
	for at, item := range block.Items {
		if item.Rec == nil {
			continue
		}
		id, _ := item.Rec.Value(t.ID)
		parent, _ := item.Rec.Value(t.Parent)
		if up, ok := byID[parent]; ok && up != at && parent != id {
			kids[up] = append(kids[up], at)
			continue
		}
		roots = append(roots, at)
	}
	t.order(block, roots)
	for _, siblings := range kids {
		t.order(block, siblings)
	}
	return kids, roots
}

// order sorts one set of siblings by their identity, the way a tree is read:
// numerically when every identity parses, in byte order otherwise.
func (t Tree) order(block model.Block, siblings []int) {
	key := func(at int) string {
		value, _ := block.Items[at].Rec.Value(t.ID)
		return value
	}
	slices.SortStableFunc(siblings, func(a, b int) int {
		x, xErr := strconv.Atoi(key(a))
		y, yErr := strconv.Atoi(key(b))
		if xErr == nil && yErr == nil {
			return cmp.Compare(x, y)
		}
		return cmp.Compare(key(a), key(b))
	})
}

// row draws one node: its branch lead, its label with the hits on it, and the
// reason the reading layer states about it. A label the panel is too narrow
// for wraps under the branch — the continuation hangs where the label begins,
// so it reads as the node's own text and as no child of it — and the reason
// hangs there too, said beside the node it belongs to.
func (t Tree) row(item model.BlockItem, lead string, opts model.RenderOptions) []string {
	text, hits := t.label(item)
	indent := strings.Repeat(" ", displayWidth(lead))
	paintedLead := lead
	if opts.Color && lead != "" {
		paintedLead = paintLead(lead)
	}
	labelWidth := max(opts.Width-displayWidth(lead), 1)
	var rows []string
	for n, segment := range wrapCell(text, labelWidth) {
		line := paintValue(displayOf(text, segment), segmentHits(hits, segment[0], segment[1]), Paint{}, opts.Color)
		if n == 0 {
			rows = append(rows, paintedLead+line)
			continue
		}
		rows = append(rows, indent+line)
	}
	if reason := ReasonFor(item.Matches); reason != "" {
		if opts.Color {
			reason = DimPaint().Style().Render(reason)
		}
		rows = append(rows, indent+reason)
	}
	return rows
}

// paintLead colors a branch lead by nesting: each bar takes the hue of the
// level it descends from, and the branch glyph the node's own level, so a deep
// nest reads by its skeleton the way a table reads by its columns. A gap
// segment stays plain — it is four blanks nothing else would see.
func paintLead(lead string) string {
	var b strings.Builder
	at, level := 0, 1
	for at < len(lead) {
		switch {
		case strings.HasPrefix(lead[at:], branchBar):
			b.WriteString(LevelPaint(level).Style().Render(lead[at : at+len(branchBar)]))
			at += len(branchBar)
		case strings.HasPrefix(lead[at:], branchGap):
			b.WriteString(lead[at : at+len(branchGap)])
			at += len(branchGap)
		default:
			b.WriteString(LevelPaint(level).Style().Render(lead[at:]))
			return b.String()
		}
		level++
	}
	return b.String()
}

// label is one node's text and the hits that paint it, in the text's own
// coordinates. A span on a column the label carries paints that part of the
// value; one on a column it does not — the account a condition named — paints
// the node whole, because the node is what matched and no part of the line
// stands for that column. A hit with no span at all is the record's own, and
// paints the node the same way.
func (t Tree) label(item model.BlockItem) (string, []paintHit) {
	spans := make([][2]int, len(item.Rec.Fields))
	for index := range spans {
		spans[index] = [2]int{-1, -1}
	}
	var text strings.Builder
	for _, name := range t.Label {
		at := item.Rec.FieldIndex(name)
		if at < 0 || item.Rec.Fields[at].Value == "" {
			continue
		}
		if text.Len() > 0 {
			text.WriteByte(' ')
		}
		start := text.Len()
		text.WriteString(item.Rec.Fields[at].Value)
		spans[at] = [2]int{start, text.Len()}
	}
	line := text.String()
	var hits []paintHit
	for _, hit := range item.Matches {
		if !hit.Severity.IsSignal() {
			continue
		}
		if len(hit.Spans) == 0 {
			hits = append(hits, paintHit{start: 0, end: len(line), severity: hit.Severity})
			continue
		}
		for _, span := range hit.Spans {
			if span.Field < 0 || span.Field >= len(spans) || spans[span.Field][0] < 0 {
				hits = append(hits, paintHit{start: 0, end: len(line), severity: hit.Severity})
				continue
			}
			start := clamp(spans[span.Field][0]+span.Start, 0, len(line))
			end := clamp(spans[span.Field][0]+span.End, 0, len(line))
			if end > start {
				hits = append(hits, paintHit{start: start, end: end, severity: hit.Severity})
			}
		}
	}
	return line, hits
}
