// listing: the directory-listing tier. The same sections, rows, and caps
// script.ListingSections prints, produced by readdir + lstat in process.

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

// listingSection writes one "== dir" section with its ListingFind rows.
func listingSection(b *strings.Builder, dir string, head int, names *nameCache) {
	fmt.Fprintf(b, "== %s\n", dir)
	for _, row := range listingRows(dir, head, names) {
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
