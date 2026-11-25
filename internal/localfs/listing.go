// The built-in listing: rows in find -printf shape sorted by mtime descending.
// Ls is the reader the `karma local ls` command prints.

package localfs

import (
	"os"
	"strings"

	"karma/internal/script"
	"karma/internal/section"
)

// Ls lists a path list with listingRows: a directory operand gets no head cap,
// and the epoch prefix is cut by rowBody. A path that is not a directory
// prints its own LsBody row, the way ls does; a symlink operand follows to
// its target for the directory decision and keeps the link row on a file.
// Several paths print one "== path" header per path — the report's own section
// spelling — so the directories read apart, while a single path prints its rows
// alone, the way ls itself drops the header. A path that
// fails leaves its section out and its error with the caller while the rest
// still print. Nothing here runs a host binary, so a preload hook on ls
// cannot reshape the answer.
func Ls(paths []string) (string, error) {
	var b strings.Builder
	var first error
	names := NewNameCache()
	for _, path := range paths {
		rows, err := lsPath(path, names)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if len(paths) > 1 {
			b.WriteString(section.Line(path))
		}
		for _, row := range script.AlignLsBodies(rows) {
			b.WriteString(row)
			b.WriteByte('\n')
		}
	}
	return b.String(), first
}

// lsPath is one operand of Ls: a directory's listingRows, or a non-directory's
// own LsBody row.
func lsPath(path string, names *NameCache) ([]string, error) {
	target, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !target.IsDir() {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		return []string{LsBody(info, path, names)}, nil
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
