// The find and grep replacements: a tree walk with find's depth and -xdev
// semantics, and a recursive content scan with grep -rnI's row shape.

package localfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// errStopWalk ends a walk early when a visitor has what it needs.
var errStopWalk = errors.New("walk stopped by visitor")

// WalkTree is the shared find replacement: lexical order, -xdev
// (cross-device directories pruned), a depth cap counting the starting point
// as depth 0 (find semantics), and prune, called for directories only — a
// pruned directory is neither visited nor descended. visit runs for every
// remaining entry including the root and returns false to end the walk;
// unreadable entries skip quietly (find's stderr is dropped), and a cancelled
// context stops the walk so the entries already visited stay with the caller.
func WalkTree(ctx context.Context, root string, maxDepth int, xdev bool,
	prune func(path string, info os.FileInfo) bool,
	visit func(path string, info os.FileInfo) bool) error {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil
	}
	rootDev := StatOf(rootInfo).Dev
	rootBase := strings.TrimSuffix(root, "/")
	if rootBase == "" {
		rootBase = "/"
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return nil // unreadable: skip quietly, siblings continue
		case ctx.Err() != nil:
			return ctx.Err()
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if d.IsDir() {
			if (prune != nil && prune(path, info)) ||
				(xdev && path != root && StatOf(info).Dev != rootDev) {
				return filepath.SkipDir
			}
			if !visit(path, info) {
				return errStopWalk
			}
			// find -maxdepth N lists a directory at depth N itself but does
			// not descend into it
			if maxDepth > 0 && pathDepth(rootBase, path) >= maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if maxDepth > 0 && pathDepth(rootBase, path) > maxDepth {
			return nil
		}
		if !visit(path, info) {
			return errStopWalk
		}
		return nil
	})
	if errors.Is(err, errStopWalk) {
		return nil
	}
	return err
}

// pathDepth is a path's find depth under rootBase: the root is 0, direct
// children 1.
func pathDepth(rootBase, path string) int {
	if path == rootBase {
		return 0
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(path, rootBase), "/")
	return strings.Count(rel, "/") + 1
}

// GrepScan describes one recursive content scan: the shape of grep -rnI with
// --include and friends. The check hands in the pattern and the file-name
// lists, so its script's grep and this walk cannot drift apart.
type GrepScan struct {
	Pattern     *regexp.Regexp // case-folded upfront when the script spelled -i
	Includes    []string       // --include basename globs; empty matches every file
	Excludes    []string       // --exclude basename globs
	ExcludeDirs []string       // --exclude-dir names, pruned at any depth
	MaxHits     int            // head cap after the pipe; 0 for none
}

// Grep is GrepScan's tier: every root's hits in grep's "path:lineno:line"
// shape, in walk order.
func Grep(roots []string, scan GrepScan) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		for _, root := range roots {
			if ctx.Err() != nil {
				return b.String(), ctx.Err()
			}
			for _, hit := range GrepWalk(ctx, root, scan) {
				b.WriteString(hit)
				b.WriteByte('\n')
			}
		}
		return b.String(), nil
	}
}

// GrepWalk reproduces grep -rnI over one root: "path:lineno:line" rows.
// Symlinked directories stay unvisited (grep -r), a symlink to a regular file
// is read, and a file containing a NUL byte is skipped (-I). The returned
// slice is already ordered by the walk.
func GrepWalk(ctx context.Context, root string, opt GrepScan) []string {
	var hits []string
	prune := func(path string, _ os.FileInfo) bool {
		return slices.Contains(opt.ExcludeDirs, filepath.Base(path))
	}
	visit := func(path string, info os.FileInfo) bool {
		if info.IsDir() {
			return true
		}
		name := filepath.Base(path)
		if MatchAny(opt.Excludes, name) {
			return true
		}
		if len(opt.Includes) > 0 && !MatchAny(opt.Includes, name) {
			return true
		}
		if info.Mode()&os.ModeSymlink != 0 {
			followed, err := os.Stat(path)
			if err != nil || !followed.Mode().IsRegular() {
				return true
			}
		} else if !info.Mode().IsRegular() {
			return true
		}
		data, err := os.ReadFile(path)
		if err != nil || bytes.IndexByte(data, 0) >= 0 {
			return true
		}
		// SplitSeq splits on \n alone, the way grep does, and without building the
		// file's whole line slice (a scanned log can be tens of MB).
		number := 0
		for line := range strings.SplitSeq(string(data), "\n") {
			number++
			if opt.Pattern.MatchString(line) {
				hits = append(hits, fmt.Sprintf("%s:%d:%s", path, number, line))
				if opt.MaxHits > 0 && len(hits) >= opt.MaxHits {
					return false
				}
			}
		}
		return true
	}
	_ = WalkTree(ctx, root, 0, false, prune, visit)
	return hits
}

// MatchAny reports whether a basename matches any of the globs, the test
// behind -iname/-name lists and --include/--exclude.
func MatchAny(globs []string, name string) bool {
	for _, pattern := range globs {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}
