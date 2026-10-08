// native tiers of the filesystem checks: fstab, SUID/SGID walks, the home
// tree, web-directory recency, webshell content signatures, and capabilities.

package native

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"karma/internal/localfs"
	"karma/internal/model"
	"karma/internal/runstate"
)

// privilegeRoots is the privilege walk's root list: the root filesystem first,
// then every mount of a local storage type from the kernel's mount table. A
// setuid binary dropped on a data disk or in a tmpfs /tmp is as much evidence as
// one under /usr/bin, and find -xdev would have missed both. A device-backed
// filesystem mounted a second time (a bind mount, a container root) is walked
// once: it is the same files, and the root pass already descends into it, since
// -xdev prunes by device rather than by mount point. Pseudo sources ("tmpfs",
// "overlay") are shared names, so two of them are two filesystems and both
// count.
func privilegeRoots(rows []mountRow, fsTypes []string) []string {
	allowed := make(map[string]bool, len(fsTypes))
	for _, fsType := range fsTypes {
		allowed[fsType] = true
	}
	roots := []string{"/"}
	seen := map[string]bool{}
	for _, row := range rows {
		if row.point == "/" {
			if deviceBacked(row.dev) {
				seen[row.dev] = true
			}
			continue
		}
		if !allowed[row.fstype] {
			continue
		}
		if deviceBacked(row.dev) {
			if seen[row.dev] {
				continue
			}
			seen[row.dev] = true
		}
		roots = append(roots, row.point)
	}
	return roots
}

// deviceBacked reports whether a mount's source names a block device.
func deviceBacked(dev string) bool { return strings.HasPrefix(dev, "/dev/") }

// privilegeWalkRoots applies privilegeRoots to the kernel's mount table;
// without one the walk falls back to the root filesystem, which is what it
// covered on its own.
func privilegeWalkRoots(fsTypes []string) []string {
	rows, ok := readMounts()
	if !ok {
		return []string{"/"}
	}
	return privilegeRoots(rows, fsTypes)
}

// scanPrivFiles walks the roots collecting the regular files carrying each of
// bits — find -perm -NNNN per bit over one traversal per root, the lists in walk
// order — and the capability rows the same passes read. A file carrying two of
// the bits lands in both lists, the way two separate finds would report it.
func scanPrivFiles(ctx context.Context, roots []string, bits ...os.FileMode) ([][]string, []string, error) {
	lists := make([][]string, len(bits))
	var caps []string
	for _, root := range roots {
		if ctx.Err() != nil {
			return lists, caps, ctx.Err()
		}
		err := localfs.WalkTree(ctx, root, 0, true, nil, func(path string, info os.FileInfo) bool {
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
		if err != nil {
			return lists, caps, err
		}
	}
	return lists, caps, nil
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

// sharedPrivWalk walks every privilege root once for the SUID, SGID, and
// capability checks and keeps the answer for the run: the three want the same
// traversal with one question different each, and find -perm plus getcap walk
// the tree three times over — seconds on a large host, and three times the
// syscall load while every other check competes for the same cache.
func sharedPrivWalk(ctx context.Context, fsTypes []string) privWalk {
	scan := func() privWalk {
		lists, caps, err := scanPrivFiles(ctx, privilegeWalkRoots(fsTypes), os.ModeSetuid, os.ModeSetgid)
		return privWalk{lists: lists, caps: caps, err: err}
	}
	walk := runstate.Memo(ctx, runstate.From(ctx), privWalkKey{}, scan)
	if walkCut(walk.err) && ctx.Err() == nil {
		// Another check's deadline cut the shared walk while this one still has
		// time: read our own rather than inherit the fragment, the rule
		// procSnapshot applies to its own shared read.
		return scan()
	}
	return walk
}

// walkCut reports whether a walk ended on a context rather than on a host
// surface it looked for.
func walkCut(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// ModeBitScan is the privilege-bit tier: the shared walk's list for one bit,
// printed as find's one path per line. fsTypes is the check's local storage
// vocabulary, the mounts the walk adds to the root filesystem.
func ModeBitScan(bit os.FileMode, fsTypes []string) func(context.Context) (string, error) {
	index := 0
	if bit == os.ModeSetgid {
		index = 1
	}
	return func(ctx context.Context) (string, error) {
		walk := sharedPrivWalk(ctx, fsTypes)
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

// FileCaps is the capability tier: the shared walk's rows, which are getcap's
// own shape. A platform without an in-process xattr read leaves the tier to the
// host's getcap.
func FileCaps(fsTypes []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if !capsInProcess() {
			return "", model.ErrTierUnavailable
		}
		walk := sharedPrivWalk(ctx, fsTypes)
		var b strings.Builder
		for _, row := range walk.caps {
			b.WriteString(row)
			b.WriteByte('\n')
		}
		return b.String(), walk.err
	}
}

// HomeTree is the home-tree tier: tree's own output when installed, otherwise
// the walk's rows — ls -l shape, one entry per row, bounded by depth. tree
// crosses mount points unless -x is given and the check does not pass it, so the
// walk crosses too. The root, the flags and the depth come from the check, which
// is also what draws the walk's rows as the tree tree(1) would have drawn.
func HomeTree(root string, flags []string, depth int) func(context.Context) (string, error) {
	argv := slices.Concat([]string{"tree"}, flags, []string{"-L", strconv.Itoa(depth), root})
	return func(ctx context.Context) (string, error) {
		if haveBinary("tree") {
			if res := runHost(ctx, argv, false); strings.TrimSpace(res.out) != "" {
				return res.out, nil
			}
		}
		var b strings.Builder
		names := localfs.NewNameCache()
		// The root is listed like any other entry, the way the find fallback
		// prints it: the reading layer draws the tree from these rows, and the
		// root's own row is what fixes the drawing's root and its level.
		err := localfs.WalkTree(ctx, root, depth, false, nil, func(path string, info os.FileInfo) bool {
			b.WriteString(localfs.LsBody(info, path, names))
			b.WriteByte('\n')
			return true
		})
		return b.String(), err
	}
}

// RecentScan is one recency walk: the roots, the name suffixes that count, how
// deep to go, and the mtime window. The check hands these in, so its rules and
// this walk cover the same files. The walk crosses devices on purpose: a
// bind-mounted web root is where the scripts live, and depth plus the mtime
// window bound the work.
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
			err := localfs.WalkTree(ctx, root, scan.MaxDepth, false, nil, func(path string, info os.FileInfo) bool {
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
