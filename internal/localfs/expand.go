// Path word lists: the shell's own expansions (globs, $(uname -r)) and the
// [ -f ] / [ -d ] guards the collection scripts put behind them.

package localfs

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// hasGlobMeta reports whether a path word carries shell glob characters.
func hasGlobMeta(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

// shellGlob expands one pattern the way a POSIX shell does. filepath.Glob has
// no dot-file rule: a "*" matches a leading dot, while the shell only matches
// one the pattern spells out, so a directory holding .placeholder yields a
// result the script tier's glob would not produce.
func shellGlob(pattern string) []string {
	matches, _ := filepath.Glob(pattern)
	if len(matches) == 0 {
		return nil
	}
	words := strings.Split(pattern, "/")
	return slices.DeleteFunc(matches, func(path string) bool {
		parts := strings.Split(path, "/")
		if len(parts) != len(words) {
			return false
		}
		for i, word := range words {
			if !hasGlobMeta(word) || strings.HasPrefix(word, ".") {
				continue
			}
			if strings.HasPrefix(parts[i], ".") {
				return true
			}
		}
		return false
	})
}

// ExpandGlobs expands a path word list the way the script tier's shell does:
// globs are expanded (sorted, and a dot name only when the pattern spells the
// dot) while a bare path is taken as it stands, and only the entries keep
// accepts survive. It is the one spelling of the `for f in …; do [ -f "$f" ]`
// guard (regular files) and of `for d in …; do [ -d "$d" ]` (directories).
func ExpandGlobs(patterns []string, keep func(os.FileInfo) bool) []string {
	var paths []string
	for _, pattern := range patterns {
		if hasGlobMeta(pattern) {
			paths = append(paths, shellGlob(pattern)...)
			continue
		}
		paths = append(paths, pattern)
	}
	return slices.DeleteFunc(paths, func(path string) bool {
		info, err := os.Stat(path)
		return err != nil || !keep(info)
	})
}

// ExpandFiles expands a path word list down to the existing regular files,
// matching the ReadFiles loop's test.
func ExpandFiles(patterns []string) []string {
	return ExpandGlobs(patterns, func(info os.FileInfo) bool { return info.Mode().IsRegular() })
}

// ExpandDirs expands a directory word list the way the script tier's shell
// does: $(uname -r) is substituted from the kernel release, a glob is expanded
// (dot-file names only when the pattern spells the dot) keeping only the
// directories it names — a plain file in the word list makes find print nothing
// either way — and a glob that matches nothing contributes nothing, so its
// section body comes back empty and the reader drops it. A word without glob
// characters passes through as it stands, so a directory that does not exist
// still yields its (empty) section.
func ExpandDirs(dirs []string) []string {
	release, _ := KernelRelease()
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

// KernelRelease reads the kernel release the shell's `$(uname -r)` prints, from
// the procfs file that backs it, without spawning a process. It is the one
// kernel fact this package needs, because the checks' directory lists spell
// `/lib/modules/$(uname -r)` literally and the target shell expands it.
func KernelRelease() (string, bool) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}
