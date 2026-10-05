// listing: the directory-listing tier. The same sections, rows, and caps
// script.ListingSections prints, produced by readdir + lstat in process; Ls is
// the single-directory reader form of the same rows.

package native

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// expandDirs expands a directory word list the way the script tier's shell
// does: $(uname -r) is substituted from /proc, globs are expanded (dot-file
// names only when the pattern spells the dot) and keep only directories (a
// file in the word list makes find print nothing either way), and a
// non-matching glob stays literal — its section body comes back empty and the
// reader drops it.
func expandDirs(dirs []string) []string {
	release, _ := kernelRelease()
	var out []string
	for _, dir := range dirs {
		if strings.Contains(dir, "$(uname -r)") {
			dir = strings.ReplaceAll(dir, "$(uname -r)", release)
		}
		if hasGlobMeta(dir) {
			matches := shellGlob(dir)
			for _, match := range matches {
				if info, err := os.Stat(match); err == nil && info.IsDir() {
					out = append(out, match)
				}
			}
			continue
		}
		out = append(out, dir)
	}
	return out
}

// listingSection writes one "== dir" section with its ListingFind rows. An
// unreadable directory leaves the section empty, the way the find pipeline
// drops its stderr.
func listingSection(b *strings.Builder, dir string, head int, names *nameCache) {
	fmt.Fprintf(b, "== %s\n", dir)
	rows, _ := listingRows(dir, head, names)
	for _, row := range rows {
		b.WriteString(row)
		b.WriteByte('\n')
	}
}

// Listing is the listing tier's in-process branch: one section per
// directory, rows in find -printf shape sorted by mtime descending,
// head-capped per section — exactly the rows ListingSections' find pipeline
// prints.
func Listing(dirs []string, head int) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		names := newNameCache()
		for _, dir := range expandDirs(dirs) {
			if ctx.Err() != nil {
				return b.String(), ctx.Err()
			}
			listingSection(&b, dir, head, names)
		}
		return b.String(), nil
	}
}

// Ls is the reader form of listingRows over a path list. A directory operand
// is that function with no head cap, and the epoch prefix cut off by rowBody,
// so the rows are the ones the panels display. A path that is not a directory
// prints its own lsBody row, the way ls does; a symlink operand follows to
// its target for the directory decision and keeps the link row on a file.
// Several paths print one "== path" section per path — the collection
// sections' own header — so the directories read apart, while a single path
// prints its rows alone, the way ls itself drops the header. A path that
// fails leaves its section out and its error with the caller while the rest
// still print. Nothing here runs a host binary, so a preload hook on ls
// cannot reshape the answer.
func Ls(paths []string) (string, error) {
	var b strings.Builder
	var first error
	names := newNameCache()
	for _, path := range paths {
		rows, err := lsPath(path, names)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if len(paths) > 1 {
			fmt.Fprintf(&b, "== %s\n", path)
		}
		for _, row := range alignLsBodies(rows) {
			b.WriteString(row)
			b.WriteByte('\n')
		}
	}
	return b.String(), first
}

// alignLsBodies lines one listing's columns up the way ls -l lays them out:
// each of the eight leading fields starts in the same column for every row,
// links and size right-aligned, owner and group left-aligned. The path is
// taken as it is — it may hold spaces itself — so the rows are split with a
// bounded count. A row that does not carry the eight fields is passed
// through, and a single row has nothing to line up with.
//
// text/tabwriter is the obvious library here, but it aligns a whole table one
// way; this row shape wants the numeric columns right-aligned and the rest
// left-aligned, so the measured widths go into one fmt format and fmt does the
// padding.
func alignLsBodies(rows []string) []string {
	if len(rows) < 2 {
		return rows
	}
	split := make([][]string, len(rows))
	width := make([]int, 8)
	for i, row := range rows {
		fields := strings.SplitN(row, " ", 9)
		if len(fields) != 9 {
			continue
		}
		split[i] = fields
		for column := range 8 {
			width[column] = max(width[column], len(fields[column]))
		}
	}
	// perms, links, owner, group, size, then the date, the clock, and the path
	format := fmt.Sprintf("%%-%ds %%%ds %%-%ds %%-%ds %%%ds %%s %%s %%s %%s",
		width[0], width[1], width[2], width[3], width[4])
	aligned := make([]string, len(rows))
	for i, fields := range split {
		if fields == nil {
			aligned[i] = rows[i]
			continue
		}
		aligned[i] = fmt.Sprintf(format,
			fields[0], fields[1], fields[2], fields[3], fields[4],
			fields[5], fields[6], fields[7], fields[8])
	}
	return aligned
}

// lsPath is one operand of Ls: a directory's listingRows, shown as the panels
// show them, or a non-directory's own lsBody row.
func lsPath(path string, names *nameCache) ([]string, error) {
	target, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !target.IsDir() {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		return []string{lsBody(info, path, names)}, nil
	}
	rows, err := listingRows(path, 0, names)
	if err != nil {
		return nil, err
	}
	bodies := make([]string, len(rows))
	for i, row := range rows {
		bodies[i] = rowBody(row)
	}
	return bodies, nil
}
