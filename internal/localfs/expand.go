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

// shellGlob expands one pattern the way a POSIX shell does: every word matches
// one path segment of a name that exists, and a wildcard never matches a leading
// dot — a dot name comes back only when the pattern itself spells the dot. The
// results are sorted, like the shell's own expansion.
//
// filepath.Glob has no dot rule (its "*" matches a leading dot), and applying
// one to its results means re-aligning them with the pattern's own words and
// hoping the two line up. Matching word by word applies the rule where it
// belongs, and there is nothing left to align.
func shellGlob(pattern string) []string {
	words := strings.Split(pattern, "/")
	dirs := []string{"."}
	if words[0] == "" {
		// An absolute pattern: the leading empty word is the root.
		dirs, words = []string{"/"}, words[1:]
	}
	// A trailing empty word is the pattern's trailing slash: the shell then
	// keeps directories only, which the last word's match applies.
	dirsOnly := false
	if last := len(words) - 1; last > 0 && words[last] == "" {
		words, dirsOnly = words[:last], true
	}
	for index, word := range words {
		last := index == len(words)-1
		var next []string
		for _, dir := range dirs {
			next = append(next, matchWord(dir, word, last, dirsOnly && last)...)
		}
		if len(next) == 0 {
			return nil
		}
		dirs = next
	}
	slices.Sort(dirs)
	return dirs
}

// matchWord matches one pattern word against one directory's entries; last marks
// the pattern's own last word, and wantDir keeps directories only (the word
// before a trailing slash). An intermediate word has to name a directory to have
// anything under it, and a symlink to one counts, the way the shell and
// filepath.Glob follow it.
func matchWord(dir, word string, last, wantDir bool) []string {
	if word == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	spellsDot := strings.HasPrefix(word, ".")
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if !spellsDot && strings.HasPrefix(name, ".") {
			continue
		}
		if matched, _ := filepath.Match(word, name); !matched {
			continue
		}
		path := filepath.Join(dir, name)
		if wantDir || !last {
			info, err := os.Stat(path)
			if err != nil || !info.IsDir() {
				continue
			}
		}
		out = append(out, path)
	}
	return out
}

// ExpandGlobs expands a path word list the way the sh source's shell does:
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

// ExpandDirs expands a directory word list the way the sh source's shell
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
