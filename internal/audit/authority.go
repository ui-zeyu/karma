package audit

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// authorityFiles are the objects whose content grants authority without being
// executed by name: the sudo policy, the account databases, the host's own ssh
// keys, and root's authorized keys.
var authorityFiles = []string{
	"/etc/sudoers",
	"/etc/sudoers.d/*",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/ssh/ssh_host_*_key",
}

// authorityRoots are walked for setuid and file-capability objects. The
// distribution's program trees and the administrator's install trees are the
// places an execution can acquire an authority the caller did not have.
var authorityRoots = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin",
	"/usr/lib", "/usr/libexec", "/usr/local", "/opt", "/etc",
}

// authoritySkip keeps the walk out of trees that carry no executable
// authority and can be very large.
var authoritySkip = []string{
	"/usr/lib/modules", "/usr/lib/firmware", "/usr/lib/debug",
	"/usr/share", "/usr/lib/python", "/usr/lib/ruby", "/usr/lib/node_modules",
}

const authorityLimit = 200000

func collectAuthority(ctx context.Context) ([]string, []string) {
	seen := map[string]bool{}
	var paths []string
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		paths = append(paths, path)
	}
	for _, pattern := range authorityFiles {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range matches {
			add(path)
		}
	}
	var gaps []string
	visited := 0
	for _, root := range authorityRoots {
		if err := ctx.Err(); err != nil {
			break
		}
		if _, err := os.Stat(root); err != nil {
			continue
		}
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if entry.IsDir() {
				for _, skip := range authoritySkip {
					if path == skip {
						return filepath.SkipDir
					}
				}
				return nil
			}
			visited++
			if visited > authorityLimit {
				gaps = append(gaps, "authority walk stopped at its file limit")
				return filepath.SkipAll
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			if info.Mode()&os.ModeSetuid == 0 && !hasCaps(path) {
				return nil
			}
			add(path)
			return nil
		})
		if err != nil {
			gaps = append(gaps, "authority walk of "+root+": "+err.Error())
		}
	}
	sort.Strings(paths)
	return paths, gaps
}
