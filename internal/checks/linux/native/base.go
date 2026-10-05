// native_base holds the shared building blocks of the native (local-channel)
// tier. Every helper reproduces its shell-tier counterpart's text exactly —
// host commands print their own stdout, file reads keep the ReadFiles section
// shape, listings keep the find -printf row shape — so the rules, filters, and
// lexers apply to both tiers unchanged. Shell-level plumbing (globs, word
// lists, loops, pipes) is what becomes Go here.

package native

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// hostResult is one host command's stdout plus whether it exited zero: the
// script tier's `cmd || next` ladders decide on the exit code while its
// `2>/dev/null` pipes keep stdout only, and output already written survives a
// timeout (harvest semantics).
type hostResult struct {
	out string
	ok  bool
}

// runHost execs one host command without a shell; the variable is swapped in
// tests. cLocale pins ls -l month names to the C spelling, the locale the
// script tier sets with LC_ALL=C.
var runHost = defaultRunHost

func defaultRunHost(ctx context.Context, argv []string, cLocale bool) hostResult {
	if len(argv) == 0 {
		return hostResult{}
	}
	if _, err := exec.LookPath(argv[0]); err != nil {
		return hostResult{}
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if cLocale {
		cmd.Env = append(os.Environ(), "LC_ALL=C")
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return hostResult{out: out.String(), ok: err == nil}
}

// hasGlobMeta reports whether a path word carries shell glob characters.
func hasGlobMeta(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

// haveBinary mirrors the scripts' `command -v` guards: the ladder decides
// availability itself instead of declaring Requires, so the runner keeps
// falling through within the one native tier.
func haveBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// procPIDs lists /proc's numeric entries in lexical order — the order the
// scripts' /proc/[0-9]* globs expand to.
func procPIDs() []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []string
	for _, entry := range entries {
		name := entry.Name()
		if name != "" && strings.Trim(name, "0123456789") == "" {
			pids = append(pids, name)
		}
	}
	return pids
}

// expandFiles expands a path word list the way the script tier's shell does:
// globs are expanded (sorted, kept literally on no match — the [ -f ] guard
// drops them either way) and only existing regular files survive, matching the
// ReadFiles loop's test.
func expandFiles(patterns []string) []string {
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
		return err != nil || !info.Mode().IsRegular()
	})
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

// ReadSections mirrors script.ReadFiles: one "== path" section per existing
// regular file, in word-list order with glob results sorted; transform shapes
// the body (nil keeps the file as read). An unreadable file still prints its
// section with an empty body, like `cat "$f" 2>/dev/null`.
func ReadSections(patterns []string, transform func(string) string) string {
	var b strings.Builder
	for _, path := range expandFiles(patterns) {
		fmt.Fprintf(&b, "== %s\n", path)
		text := ""
		if body, err := os.ReadFile(path); err == nil {
			text = string(body)
		}
		if transform != nil {
			text = transform(text)
		}
		b.WriteString(text)
	}
	return b.String()
}

// TailLines keeps the last n lines of a body: the script tier's `tail -n N`.
func TailLines(n int) func(string) string {
	return func(text string) string {
		if text == "" {
			return ""
		}
		lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
		return strings.Join(lines, "\n") + "\n"
	}
}

// kernelRelease reads the kernel release the way $(uname -r) does, without
// spawning a process.
func kernelRelease() (string, bool) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

// months is the C-locale month abbreviation table find's %Tb prints under
// LC_ALL=C.
var months = [...]string{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
}

// permString renders a mode in find %M shape: one type character and three
// rwx triples, with s/S/t/T in the execute positions for the special bits
// (uppercase when the execute bit itself is clear).
func permString(mode os.FileMode) string {
	kind := byte('-')
	switch {
	case mode.IsDir():
		kind = 'd'
	case mode&os.ModeSymlink != 0:
		kind = 'l'
	case mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0:
		kind = 'c'
	case mode&os.ModeDevice != 0:
		kind = 'b'
	case mode&os.ModeNamedPipe != 0:
		kind = 'p'
	case mode&os.ModeSocket != 0:
		kind = 's'
	}
	buf := []byte{kind, '-', '-', '-', '-', '-', '-', '-', '-', '-'}
	perm := mode.Perm()
	special := [3]byte{}
	if mode&os.ModeSetuid != 0 {
		special[0] = 's'
	}
	if mode&os.ModeSetgid != 0 {
		special[1] = 's'
	}
	if mode&os.ModeSticky != 0 {
		special[2] = 't'
	}
	execute := [3]bool{perm&0o100 != 0, perm&0o010 != 0, perm&0o001 != 0}
	for triple, mark := range [...]struct{ read, write bool }{
		{perm&0o400 != 0, perm&0o200 != 0},
		{perm&0o040 != 0, perm&0o020 != 0},
		{perm&0o004 != 0, perm&0o002 != 0},
	} {
		base := 1 + triple*3
		if mark.read {
			buf[base] = 'r'
		}
		if mark.write {
			buf[base+1] = 'w'
		}
		switch {
		case execute[triple] && special[triple] != 0:
			buf[base+2] = special[triple]
		case special[triple] != 0:
			buf[base+2] = special[triple] - 32 // S / T
		case execute[triple]:
			buf[base+2] = 'x'
		}
	}
	return string(buf)
}

// nameCache resolves uid/gid numbers to account names with one lookup per id,
// falling back to the number itself the way find's %u/%g do.
type nameCache struct {
	users  map[int]string
	groups map[int]string
}

func newNameCache() *nameCache {
	return &nameCache{users: map[int]string{}, groups: map[int]string{}}
}

func (n *nameCache) user(uid int) string {
	if name, ok := n.users[uid]; ok {
		return name
	}
	name := strconv.Itoa(uid)
	if entry, err := user.LookupId(name); err == nil {
		name = entry.Username
	}
	n.users[uid] = name
	return name
}

func (n *nameCache) group(gid int) string {
	if name, ok := n.groups[gid]; ok {
		return name
	}
	name := strconv.Itoa(gid)
	if entry, err := user.LookupGroupId(name); err == nil {
		name = entry.Name
	}
	n.groups[gid] = name
	return name
}

// lsBody renders one entry in script.LSBodyPrintf shape — the row the ls-l
// pseudo-lexer speaks: permissions links owner group size month day clock
// path, a symlink row appending " -> target" the way %l does.
func lsBody(info os.FileInfo, path string, names *nameCache) string {
	st := statOf(info)
	body := fmt.Sprintf("%s %d %s %s %d %s %02d %02d:%02d %s",
		permString(info.Mode()), st.nlink, names.user(st.uid), names.group(st.gid),
		info.Size(), months[st.mtime.Month()-1], st.mtime.Day(),
		st.mtime.Hour(), st.mtime.Minute(), path)
	if info.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(path); err == nil {
			body += " -> " + target
		}
	}
	return body
}

// epochFrac renders find's epoch-with-fraction field (%T@, %C@): whole seconds
// then a ten-digit fraction, which sort -rn and the cluster parser both read as
// one number. The trailing digit is always zero — find prints ten decimal
// places although timestamps stop at nanoseconds.
func epochFrac(t time.Time) string {
	return fmt.Sprintf("%d.%010d", t.Unix(), t.Nanosecond()*10)
}

// listingRows mirrors script.ListingFind: one directory's entries as
// "%T@\t%C@\t" + ls-l rows, sorted by mtime descending (ties by row text,
// sort's last-resort comparison) and capped at head.
func listingRows(dir string, head int, names *nameCache) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type listed struct {
		mtime float64
		text  string
	}
	var rows []listed
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		st := statOf(info)
		text := epochFrac(st.mtime) + "\t" + epochFrac(st.ctime) + "\t" +
			lsBody(info, filepath.Join(dir, entry.Name()), names)
		rows = append(rows, listed{mtime: secFloat(st.mtime), text: text})
	}
	slices.SortFunc(rows, func(a, b listed) int {
		if a.mtime != b.mtime {
			if a.mtime > b.mtime {
				return -1
			}
			return 1
		}
		return strings.Compare(a.text, b.text)
	})
	if len(rows) > head {
		rows = rows[:head]
	}
	texts := make([]string, len(rows))
	for i, r := range rows {
		texts[i] = r.text
	}
	return texts
}

// secFloat is an instant as seconds-with-fraction for numeric ordering.
func secFloat(t time.Time) float64 {
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}

// errStopWalk ends a walk early when a visitor has what it needs.
var errStopWalk = errors.New("walk stopped by visitor")

// walkTree is the shared find replacement: lexical order, -xdev
// (cross-device directories pruned), a depth cap counting the starting point
// as depth 0 (find semantics), and prune, called for directories only — a
// pruned directory is neither visited nor descended. visit runs for every
// remaining entry including the root and returns false to end the walk;
// unreadable entries skip quietly (find's stderr is dropped), and a cancelled
// context stops the walk so the entries already visited stay with the caller.
func walkTree(ctx context.Context, root string, maxDepth int, xdev bool,
	prune func(path string, info os.FileInfo) bool,
	visit func(path string, info os.FileInfo) bool) error {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil
	}
	rootDev := statOf(rootInfo).dev
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
				(xdev && path != root && statOf(info).dev != rootDev) {
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
			for _, hit := range grepWalk(ctx, root, scan) {
				b.WriteString(hit)
				b.WriteByte('\n')
			}
		}
		return b.String(), nil
	}
}

// grepWalk reproduces grep -rnI over one root: "path:lineno:line" rows.
// Symlinked directories stay unvisited (grep -r), a symlink to a regular file
// is read, and a file containing a NUL byte is skipped (-I). The returned
// slice is already ordered by the walk.
func grepWalk(ctx context.Context, root string, opt GrepScan) []string {
	var hits []string
	prune := func(path string, _ os.FileInfo) bool {
		return slices.Contains(opt.ExcludeDirs, filepath.Base(path))
	}
	visit := func(path string, info os.FileInfo) bool {
		if info.IsDir() {
			return true
		}
		name := filepath.Base(path)
		for _, pattern := range opt.Excludes {
			if matched, _ := filepath.Match(pattern, name); matched {
				return true
			}
		}
		if len(opt.Includes) > 0 && !matchAny(opt.Includes, name) {
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
		for i, line := range strings.Split(string(data), "\n") {
			if opt.Pattern.MatchString(line) {
				hits = append(hits, fmt.Sprintf("%s:%d:%s", path, i+1, line))
				if opt.MaxHits > 0 && len(hits) >= opt.MaxHits {
					return false
				}
			}
		}
		return true
	}
	_ = walkTree(ctx, root, 0, false, prune, visit)
	return hits
}

// matchAny reports whether a basename matches any of the globs.
func matchAny(globs []string, name string) bool {
	for _, pattern := range globs {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

// filteredLines is the in-process counterpart of the scripts' grep over a file
// it has already read: the lines keep accepts, in order, one newline each. No
// hit is an empty string rather than one empty line.
func filteredLines(data string, keep func(line string) bool) string {
	var b strings.Builder
	for _, line := range strings.Split(data, "\n") {
		if keep(line) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
