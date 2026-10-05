// native tiers of the filesystem checks: fstab, SUID/SGID walks, the home
// tree, web-directory recency, webshell content signatures, and capabilities.

package linux

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
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

// nativeModeBitScan is the privilege-bit tier: the shared walk's list for one
// bit, printed as find's one path per line.
func nativeModeBitScan(bit os.FileMode) func(context.Context) (string, error) {
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

// nativeFileCaps is the capability tier: the shared walk's rows, which are
// getcap's own shape. A platform without an in-process xattr read leaves the
// tier to the host's getcap.
func nativeFileCaps(ctx context.Context) (string, error) {
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

// homeTreeArgv is the tree tier's argument vector — the same words the script
// spells, one binary call without a shell.
var homeTreeArgv = []string{"tree", "-a", "-p", "-u", "-g", "-s", "-D",
	"--timefmt", "%Y-%m-%d %H:%M", "-L", "4", "/home"}

// nativeHomeTree mirrors the home-tree ladder: tree's own output when
// installed, otherwise the find -printf rows — ls -l shape, one per entry,
// four levels, one filesystem.
func nativeHomeTree(ctx context.Context) (string, error) {
	if haveBinary("tree") {
		if res := runHost(ctx, homeTreeArgv, false); strings.TrimSpace(res.out) != "" {
			return res.out, nil
		}
	}
	var b strings.Builder
	names := newNameCache()
	err := walkTree(ctx, "/home", 4, true, nil, func(path string, info os.FileInfo) bool {
		if path != "/home" {
			b.WriteString(lsBody(info, path, names))
			b.WriteByte('\n')
		}
		return true
	})
	return b.String(), err
}

// webScriptName matches find's -name list for recently changed web scripts.
func webScriptName(name string) bool {
	return strings.HasSuffix(name, ".php") || strings.HasSuffix(name, ".jsp") ||
		strings.HasSuffix(name, ".jspx") || strings.HasSuffix(name, ".sh") ||
		strings.HasSuffix(name, ".py")
}

// webScriptRoots and webScriptMaxDepth mirror webScriptFind's walk: three
// roots, each staying on its own filesystem, three levels deep.
var webScriptRoots = []string{"/var/www", "/usr/local/nginx", "/opt"}

// nativeWebDirs mirrors webScriptFind: scripts under the web roots modified
// within fourteen days, one path per row.
func nativeWebDirs(ctx context.Context) (string, error) {
	var b strings.Builder
	for _, root := range webScriptRoots {
		err := walkTree(ctx, root, 3, true, nil, func(path string, info os.FileInfo) bool {
			if info.Mode().IsRegular() && webScriptName(filepath.Base(path)) &&
				time.Since(info.ModTime()) < 14*24*time.Hour {
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

// webshellRe is the three signature groups in one alternation — the union the
// grep collects; the rules grade the groups separately afterwards.
var webshellRe = regexp.MustCompile(`(?i)(?:` + webshellDirect + `|` + webshellDecode + `|` + webshellCallback + `)`)

// webshellRoots is webshellGrep's directory list.
var webshellRoots = []string{"/var/www", "/srv", "/opt", "/app", "/usr/local/nginx", "/usr/share/nginx"}

// nativeWebshellGrep mirrors webshellGrep: recursive case-insensitive content
// scan over the web roots, php-family includes, .git and node_modules pruned,
// rows in grep's "path:lineno:line" shape.
func nativeWebshellGrep(ctx context.Context) (string, error) {
	var b strings.Builder
	for _, root := range webshellRoots {
		for _, hit := range grepWalk(ctx, root, grepOptions{
			pattern:     webshellRe,
			includes:    []string{"*.php", "*.phtml", "*.inc"},
			excludeDirs: []string{".git", "node_modules"},
		}) {
			b.WriteString(hit)
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}
