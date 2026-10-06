// The ls -l body row, read side: taking a collected row apart into its nine
// columns and lining a listing up the way ls -l lays it out. The shape itself
// is LSBodyPrintf in script.go; the collection side and the reading side
// (cluster's listing normalizer) both split it here, so the columns are one
// definition.

package script

import (
	"fmt"
	"strconv"
	"strings"
)

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
// by AlignLsBodies split again unchanged, so the split is safe wherever a row
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

// AlignLsBodies lines one listing's columns up the way ls -l lays them out:
// each of the eight leading fields starts in the same column for every row,
// links and size right-aligned, owner and group left-aligned. The path is taken
// as it is — it may hold spaces itself. A row that does not carry the nine
// columns is passed through, and a single row has nothing to line up with, so a
// listing of one row is returned unchanged.
//
// text/tabwriter is the obvious library here, but it aligns a whole table one
// way; this row shape wants the numeric columns right-aligned and the rest
// left-aligned, so the measured widths go into one fmt format and fmt does the
// padding.
//
// Widening a row moves the text after it, so a caller that states spans over
// these rows (the listing normalizer's outlier verdicts) measures them on the
// aligned text.
func AlignLsBodies(rows []string) []string {
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
	format := fmt.Sprintf("%%-%ds %%%ds %%-%ds %%-%ds %%%ds %%s %%s %%s %%s",
		width[0], width[1], width[2], width[3], width[4])
	aligned := make([]string, len(rows))
	for index, fields := range split {
		if fields == nil {
			aligned[index] = rows[index]
			continue
		}
		aligned[index] = fmt.Sprintf(format,
			fields[0], fields[1], fields[2], fields[3], fields[4],
			fields[5], fields[6], fields[7], linkPath(fields))
	}
	return aligned
}

// linkPath is the path column of one row, with a symlink's target separated
// the way ls -l writes it. find's %l prints the target with no arrow and
// glued to the path, so a collected row carries them as one word; the link's
// size is the target's length, which is what cuts them apart. A path that
// holds spaces survives, because the cut counts from the end. A row that
// already carries the arrow — the local channel spells it, and a second pass
// over an aligned listing — is returned as it is.
func linkPath(fields []string) string {
	path := fields[LsBodyPath]
	if fields[0] == "" || fields[0][0] != 'l' || strings.Contains(path, " -> ") {
		return path
	}
	size, err := strconv.Atoi(fields[4])
	if err != nil || size < 1 || size >= len(path) {
		return path
	}
	return path[:len(path)-size] + " -> " + path[len(path)-size:]
}
