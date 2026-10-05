// native_listing: the directory-listing tier. The same sections, rows, and
// caps script.ListingSections prints, produced by readdir + lstat in process.

package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"karma/internal/cluster"
	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
)

// listingCheck is a directory-listing check: one section per directory, rows
// in ls -l shape capped at head, clustered locally to mark outliers. The
// in-process branch and the find pipeline are two implementations of the one
// tier, so the check is declared once for both channels.
func listingCheck(id, title string, aspect model.Aspect, dirs []string, head int, rules []model.Rule) *model.Check {
	return define.LinuxCheck(id, title, aspect,
		[]model.Probe{{Label: "find", Inv: model.Dual{
			Run:    nativeListing(dirs, head),
			Script: script.ListingSections(dirs, head),
		}}},
		define.CheckOpt{Rules: rules, Syntax: "ls-l", Normalize: cluster.ListingNormalize(time.Now)})
}

// expandDirs expands a directory word list the way the script tier's shell
// does: $(uname -r) is substituted from /proc, globs are expanded and keep
// only directories (a file in the word list makes find print nothing either
// way), and a non-matching glob stays literal — its section body comes back
// empty and the reader drops it.
func expandDirs(dirs []string) []string {
	release, _ := kernelRelease()
	var out []string
	for _, dir := range dirs {
		if strings.Contains(dir, "$(uname -r)") {
			dir = strings.ReplaceAll(dir, "$(uname -r)", release)
		}
		if hasGlobMeta(dir) {
			matches, _ := filepath.Glob(dir)
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

// nativeListing is the listing tier's in-process branch: one section per
// directory, rows in find -printf shape sorted by mtime descending,
// head-capped per section — exactly the rows ListingSections' find pipeline
// prints.
func nativeListing(dirs []string, head int) func(context.Context) (string, error) {
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
