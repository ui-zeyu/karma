// Package shape holds the body shapers that turn a tool's own wording into the
// table the panel reads: ip's key-value rows become columns, fstab's six
// fields are padded to a grid, apt's transaction records become a two-column
// history, and the home walk's listing rows become the tree tree(1) draws.
//
// Every shaper is a model.Normalizer the reading pipeline runs per section,
// before rules and filters — so the tokens the rules look for survive the
// reshape, and both channels (whose raw output is the same tool wording) get
// the same table. A shaper declines the body it does not recognize by
// returning nil, which keeps the text exactly as the tool wrote it; the raw
// text --save writes is never touched by any of this.
//
// Two types carry the mechanics so no shaper hand-rolls alignment: Table pads
// columns, Tree draws branch glyphs. Determinism is the contract — same input,
// same bytes, whatever the terminal — which is why this package builds plain
// text and leaves styling to the render layer.
package shape

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"karma/internal/model"
)

// columnGap is the padding between the columns of a table these shapers
// build: two blanks, so a wide cell never touches its neighbour.
const columnGap = 2

// Table is a padded table: every column padded to its widest cell, the last
// column left exactly as the caller wrote it (a row's trailing bytes are the
// tool's own, and trailing blanks would reach the panel). A table built with
// a header prints it first; one without prints rows alone. An empty table
// renders nothing.
type Table struct {
	header []string
	rows   [][]string
}

// NewTable starts a table; the header cells are optional.
func NewTable(header ...string) *Table { return &Table{header: header} }

// Add appends one row. A row shorter than the header pads with empty cells;
// a longer one keeps its extra cells, padded like any column before the last.
func (t *Table) Add(cells ...string) { t.rows = append(t.rows, cells) }

// Empty reports whether the table holds no rows.
func (t *Table) Empty() bool { return len(t.rows) == 0 }

// String renders the table: columns padded to the widest cell among the
// header and the rows.
func (t *Table) String() string {
	if t.Empty() {
		return ""
	}
	columns := max(len(t.header), 1)
	for _, row := range t.rows {
		columns = max(columns, len(row))
	}
	widths := make([]int, columns)
	measure := func(row []string) {
		for col, cell := range row {
			widths[col] = max(widths[col], len(cell))
		}
	}
	measure(t.header)
	for _, row := range t.rows {
		measure(row)
	}
	var b strings.Builder
	writeRow := func(row []string, columns int) {
		for col := 0; col < columns; col++ {
			cell := ""
			if col < len(row) {
				cell = row[col]
			}
			if col == columns-1 {
				b.WriteString(cell)
				break
			}
			fmt.Fprintf(&b, "%-*s", widths[col]+columnGap, cell)
		}
		b.WriteByte('\n')
	}
	if len(t.header) > 0 {
		writeRow(t.header, len(t.header))
	}
	for _, row := range t.rows {
		writeRow(row, len(row))
	}
	return b.String()
}

// Tree draws one label per path with tree(1)'s branch glyphs: children in
// byte order, `├── ` between siblings, `└── ` for the last, `│` carrying the
// parent's line down. The root is the topmost path added — the shortest, shrunk
// until every other path sits under it.
type Tree struct {
	labels map[string]string
	isDir  map[string]bool
}

// NewTree starts an empty tree.
func NewTree() *Tree {
	return &Tree{labels: map[string]string{}, isDir: map[string]bool{}}
}

// Add places one path's label in the tree. isDir only decides the closing
// count of directories and files.
func (t *Tree) Add(path, label string, dir bool) {
	t.labels[path] = label
	t.isDir[path] = dir
}

// Empty reports whether the tree holds no paths.
func (t *Tree) Empty() bool { return len(t.labels) == 0 }

// String draws the tree and closes with tree's own summary line. The root's
// line carries the root's own label when the walk listed it — tree prints the
// root's attributes like any other row — and the bare path otherwise.
func (t *Tree) String() string {
	if t.Empty() {
		return ""
	}
	root := t.derivedRoot()
	children := map[string][]string{}
	for path := range t.labels {
		if path == root {
			continue
		}
		rel := strings.TrimPrefix(path, root+"/")
		parent := root
		if at := strings.LastIndex(rel, "/"); at >= 0 {
			parent = root + "/" + rel[:at]
		}
		children[parent] = append(children[parent], path)
	}
	for _, names := range children {
		slices.Sort(names)
	}
	var (
		b     strings.Builder
		dirs  int
		files int
		draw  func(dir, prefix string)
	)
	draw = func(dir, prefix string) {
		kids := children[dir]
		for i, path := range kids {
			glyph, below := "├── ", prefix+"│   "
			if i == len(kids)-1 {
				glyph, below = "└── ", prefix+"    "
			}
			if t.isDir[path] {
				dirs++
			} else {
				files++
			}
			b.WriteString(prefix + glyph + t.labels[path] + "\n")
			draw(path, below)
		}
	}
	if label, listed := t.labels[root]; listed {
		b.WriteString(label + "\n")
	} else {
		b.WriteString(root + "\n")
	}
	draw(root, "")
	b.WriteString("\n" + plural(dirs, "directory") + ", " + plural(files, "file") + "\n")
	return b.String()
}

// plural is tree's own closing line: "1 directory, 2 directories".
func plural(count int, noun string) string {
	if count == 1 {
		return "1 " + noun
	}
	if strings.HasSuffix(noun, "y") {
		return strconv.Itoa(count) + " " + noun[:len(noun)-1] + "ies"
	}
	return strconv.Itoa(count) + " " + noun + "s"
}

// derivedRoot is the topmost path: the shortest one, shrunk until every other
// path sits under it, and one level further when that shortest path is itself
// a file.
func (t *Tree) derivedRoot() string {
	paths := make([]string, 0, len(t.labels))
	for path := range t.labels {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	root := paths[0]
	for _, path := range paths[1:] {
		// The filesystem root contains every absolute path, so the shrink
		// stops there — without the guard this loop would spin on
		// parentDir("/") == "/" when two paths share nothing above it.
		for path != root && root != "/" && !strings.HasPrefix(path, root+"/") {
			root = parentDir(root)
		}
	}
	if !t.isDir[root] {
		root = parentDir(root)
	}
	return root
}

// parentDir is the directory one level up; the filesystem root is its own
// parent.
func parentDir(path string) string {
	if at := strings.LastIndex(path, "/"); at > 0 {
		return path[:at]
	}
	return "/"
}

// shaped is the one-line wrapper every shaper here ends with.
func shaped(text string) *model.Shaped { return &model.Shaped{Text: text} }

// lines splits a body the way the reading pipeline counts it, dropping the
// terminator so a trailing blank never becomes a phantom row.
func lines(body string) []string {
	return strings.Split(strings.TrimSuffix(body, "\n"), "\n")
}
