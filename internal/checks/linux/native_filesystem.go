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
)

// nativeSuidScan walks / on one device collecting files carrying the mode bit
// — find -perm -NNNN in process, so the listing answers even where GNU find is
// missing.
func nativeSuidScan(bit os.FileMode) func(context.Context) (string, error) {
	return nativeSuidScanRoot("/", bit)
}

func nativeSuidScanRoot(root string, bit os.FileMode) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		err := walkTree(ctx, root, 0, true, nil, func(path string, info os.FileInfo) bool {
			if info.Mode().IsRegular() && info.Mode()&bit != 0 {
				b.WriteString(path)
				b.WriteByte('\n')
			}
			return true
		})
		return b.String(), err
	}
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

// nativeCaps mirrors the getcap tier: the recursive capability listing, run
// without a shell.
func nativeCaps(ctx context.Context) (string, error) {
	if !haveBinary("getcap") {
		return "", model.ErrTierUnavailable
	}
	return runHost(ctx, []string{"getcap", "-r", "/"}, false).out, nil
}
