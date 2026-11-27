// Package localfs owns the host's file reads: the one non-blocking regular
// file opener, the ls -l row shape and its reading side, and the built-in
// listing.

package localfs

import (
	"strconv"
	"strings"

	chrome "karma/internal/panel"
)

// LSBodyPrintf is the ls -l row shape: permissions links owner group size date
// clock path. A symlink row appends its target with no arrow (find's %l prints
// the target alone); the reading side separates path and target.
const LSBodyPrintf = `%M %n %u %g %s %Tb %Td %TH:%TM %p%l\n`

// lsBodyColumns is the number of columns of an ls -l body row: permissions,
// links, owner, group, size, month, day, clock, path.
const lsBodyColumns = 9

// LsBodyPath is the path column's index in SplitLsBody's result: the last of
// the nine columns, and the field a caller reads a row's path from.
const LsBodyPath = lsBodyColumns - 1

// SplitLsBody splits one ls -l body row into its nine columns. Columns are
// separated by one or more spaces and the path is the rest of the row, which
// may hold spaces itself; a row that does not carry nine columns, or whose
// first column is not a permission string, is rejected. Rows already lined up
// by alignLsBodies split again unchanged, so the split is safe wherever a row
// comes from.
func SplitLsBody(row string) ([]string, bool) {
	fields := make([]string, 0, lsBodyColumns)
	rest := row
	for len(fields) < lsBodyColumns-1 {
		field, tail, ok := cutField(rest)
		if !ok {
			return nil, false
		}
		fields = append(fields, field)
		rest = tail
	}
	if rest == "" || !looksLikePermissions(fields[0]) {
		return nil, false
	}
	return append(fields, rest), true
}

// looksLikePermissions reports whether a row's first column is the permission
// string the shape starts with: a file type character and the nine mode bits,
// with room for a trailing attribute mark (GNU ls writes + or ., BSD/macOS @).
// A section holds rows that are not listings too — a grep hit, a remark — and
// this is what keeps them from being read as ls -l rows and padded.
func looksLikePermissions(field string) bool {
	if len(field) < 10 || len(field) > 12 {
		return false
	}
	if !strings.ContainsRune("-dlbcps", rune(field[0])) {
		return false
	}
	for _, flag := range field[1:] {
		if !strings.ContainsRune("rwxsStT-+@.", flag) {
			return false
		}
	}
	return true
}

// cutField cuts one field off a row: up to the next run of spaces, which is the
// separator and is consumed with it. A row with no separator left has no more
// fields.
func cutField(row string) (field, rest string, ok bool) {
	gap := strings.IndexByte(row, ' ')
	if gap < 0 {
		return "", "", false
	}
	end := gap
	for end < len(row) && row[end] == ' ' {
		end++
	}
	return row[:gap], row[end:], true
}

// alignLsBodies lines one listing's columns up the way ls -l lays them out:
// each of the eight leading fields starts in the same column for every row,
// links and size right-aligned, owner and group left-aligned. The path is taken
// as it is — it may hold spaces itself. A row that does not carry the nine
// columns is passed through, and a single row has nothing to line up with, so a
// listing of one row keeps its own spacing.
//
// Every row's path is repaired first (linkRow), so a collected symlink row —
// find's %l prints the target glued to the path — reads like ls -l's wherever it
// stands, a section of one row included.
//
// text/tabwriter is the obvious library here, but it aligns a whole table one
// way; this row shape wants the numeric columns right-aligned and the rest
// left-aligned, so the measured widths go into one fmt format and fmt does the
// padding.
//
// Widening a row moves the text after it, so a caller that cites spans over
// these rows measures them on the aligned text.
func alignLsBodies(rows []string) []string {
	repaired := make([]string, len(rows))
	for index, row := range rows {
		repaired[index] = linkRow(row)
	}
	rows = repaired
	if len(rows) < 2 {
		return rows
	}
	split := make([][]string, len(rows))
	width := make([]int, 8)
	for index, row := range rows {
		fields, ok := SplitLsBody(row)
		if !ok {
			continue
		}
		split[index] = fields
		for column := range 8 {
			width[column] = max(width[column], len(fields[column]))
		}
	}
	// perms, links, owner, group, size, then the date, the clock, and the path
	aligned := make([]string, len(rows))
	for index, fields := range split {
		if fields == nil {
			aligned[index] = rows[index]
			continue
		}
		var line strings.Builder
		for column := 0; column < 8; column++ {
			if column > 0 {
				line.WriteByte(' ')
			}
			line.WriteString(padCell(fields[column], width[column], column == 1 || column == 4))
		}
		line.WriteByte(' ')
		line.WriteString(fields[LsBodyPath])
		aligned[index] = line.String()
	}
	return aligned
}

func padCell(text string, width int, right bool) string {
	gap := width - chrome.DisplayWidth(text)
	if gap <= 0 {
		return text
	}
	padding := strings.Repeat(" ", gap)
	if right {
		return padding + text
	}
	return text + padding
}

// linkRow is one row with a symlink's target separated the way ls -l writes it.
// find's %l prints the target with no arrow and glued to the path, so a row the
// target's own find produced carries them as one word; the link's size is the
// target's length, which is what cuts them apart. A path that holds spaces
// survives, because the cut counts from the end. A row that already carries the
// arrow — the native source's own listing spells it, and a second pass over an
// aligned listing — or that is not a symlink listing at all is returned as it
// came.
func linkRow(row string) string {
	fields, ok := SplitLsBody(row)
	if !ok || fields[0] == "" || fields[0][0] != 'l' {
		return row
	}
	path := fields[LsBodyPath]
	if strings.Contains(path, " -> ") {
		return row
	}
	size, err := strconv.Atoi(fields[4])
	if err != nil || size < 1 || size >= len(path) {
		return row
	}
	return row[:len(row)-len(path)] + path[:len(path)-size] + " -> " + path[len(path)-size:]
}
