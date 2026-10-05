// native tiers of the filesystem checks: fstab, SUID/SGID walks, the home
// tree, web-directory recency, webshell content signatures, and capabilities.

package native

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"karma/internal/model"
	"karma/internal/runstate"
)

// scanPrivFiles walks one filesystem collecting the regular files carrying each
// of bits — find -perm -NNNN per bit over a single traversal, the lists in walk
// order — and the capability rows the same pass reads. A file carrying two of
// the bits lands in both lists, the way two separate finds would report it.
func scanPrivFiles(ctx context.Context, root string, bits ...os.FileMode) ([][]string, []string, error) {
	lists := make([][]string, len(bits))
	var caps []string
	err := walkTree(ctx, root, 0, true, nil, func(path string, info os.FileInfo) bool {
		mode := info.Mode()
		if !mode.IsRegular() {
			return true
		}
		for i, bit := range bits {
			if mode&bit != 0 {
				lists[i] = append(lists[i], path)
			}
		}
		if row := fileCapsRow(path); row != "" {
			caps = append(caps, row)
		}
		return true
	})
	return lists, caps, err
}

// privWalkKey is the store key of the privilege walk the SUID, SGID, and
// capability checks share.
type privWalkKey struct{}

// privWalk is that walk's answer: one path list per requested bit, then the
// capability rows.
type privWalk struct {
	lists [][]string
	caps  []string
	err   error
}

// sharedPrivWalk walks / once for the SUID, SGID, and capability checks and
// keeps the answer for the run: the three want the same traversal with one
// question different each, and find -perm plus getcap walk the tree three
// times over — seconds on a large host, and three times the syscall load while
// every other check competes for the same cache.
func sharedPrivWalk(ctx context.Context) privWalk {
	scan := func() privWalk {
		lists, caps, err := scanPrivFiles(ctx, "/", os.ModeSetuid, os.ModeSetgid)
		return privWalk{lists: lists, caps: caps, err: err}
	}
	store := runstate.From(ctx)
	if store == nil {
		return scan()
	}
	return runstate.Memo(store, privWalkKey{}, scan)
}

// ModeBitScan is the privilege-bit tier: the shared walk's list for one
// bit, printed as find's one path per line.
func ModeBitScan(bit os.FileMode) func(context.Context) (string, error) {
	index := 0
	if bit == os.ModeSetgid {
		index = 1
	}
	return func(ctx context.Context) (string, error) {
		walk := sharedPrivWalk(ctx)
		var b strings.Builder
		if index < len(walk.lists) {
			for _, path := range walk.lists[index] {
				b.WriteString(path)
				b.WriteByte('\n')
			}
		}
		return b.String(), walk.err
	}
}

// FileCaps is the capability tier: the shared walk's rows, which are
// getcap's own shape. A platform without an in-process xattr read leaves the
// tier to the host's getcap.
func FileCaps(ctx context.Context) (string, error) {
	if !capsInProcess() {
		return "", model.ErrTierUnavailable
	}
	walk := sharedPrivWalk(ctx)
	var b strings.Builder
	for _, row := range walk.caps {
		b.WriteString(row)
		b.WriteByte('\n')
	}
	return b.String(), walk.err
}

// HomeTree is the home-tree ladder's local branch: tree's own output when
// installed, otherwise the find -printf rows — ls -l shape, one entry per row,
// bounded by depth, one filesystem. The root and the depth come from the check,
// which spells the same two in its find command for the ssh channel.
func HomeTree(root string, depth int) func(context.Context) (string, error) {
	argv := []string{"tree", "-a", "-p", "-u", "-g", "-s", "-D",
		"--timefmt", "%Y-%m-%d %H:%M", "-L", strconv.Itoa(depth), root}
	return func(ctx context.Context) (string, error) {
		if haveBinary("tree") {
			if res := runHost(ctx, argv, false); strings.TrimSpace(res.out) != "" {
				return res.out, nil
			}
		}
		var b strings.Builder
		names := newNameCache()
		err := walkTree(ctx, root, depth, true, nil, func(path string, info os.FileInfo) bool {
			if path != root {
				b.WriteString(lsBody(info, path, names))
				b.WriteByte('\n')
			}
			return true
		})
		return b.String(), err
	}
}

// RecentScan is one recency walk: the roots, each staying on its own
// filesystem, the name suffixes that count, how deep to go, and the mtime
// window. The check hands these in, so its find -name list, its rule, and this
// walk all cover the same files.
type RecentScan struct {
	Roots    []string
	Suffixes []string
	MaxDepth int
	Window   time.Duration
}

// RecentFiles is RecentScan's tier: one path per row, in the walk's order.
func RecentFiles(scan RecentScan) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		for _, root := range scan.Roots {
			if ctx.Err() != nil {
				return b.String(), ctx.Err()
			}
			err := walkTree(ctx, root, scan.MaxDepth, true, nil, func(path string, info os.FileInfo) bool {
				if info.Mode().IsRegular() && recentName(filepath.Base(path), scan.Suffixes) &&
					time.Since(info.ModTime()) < scan.Window {
					b.WriteString(path)
					b.WriteByte('\n')
				}
				return true
			})
			if err != nil {
				return b.String(), err
			}
		}
		return b.String(), nil
	}
}

// recentName reports whether a basename ends in one of the suffixes.
func recentName(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
