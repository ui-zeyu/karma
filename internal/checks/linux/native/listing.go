// listing: the directory-listing tier. The same sections, rows, and caps
// script.ListingSections prints, produced by readdir + lstat in process; Ls is
// the single-directory reader form of the same rows.

package native

import (
	"context"
	"fmt"
	"os"
	"strings"

	"karma/internal/script"
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
		for _, row := range script.AlignLsBodies(rows) {
			b.WriteString(row)
			b.WriteByte('\n')
		}
	}
	return b.String(), first
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
