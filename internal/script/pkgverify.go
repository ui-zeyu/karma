// The package-verify body: what changed, without the wall of text a slimmed
// image produces. A package db that disagrees with the image's documentation,
// locale and man files is noise the analyst has to scroll past to reach the two
// binaries that matter, so the body names the files that can be a finding — an
// ELF object, an executable, a conffile — one by one with their type and
// attributes, and counts the rest per directory, noting how many of them are
// gone rather than modified.
//
// Two implementations render that body and must agree word for word: this
// file's Go side (PkgVerifyBody, the local channel) and the awk pipeline the
// ssh and ttyd channels run (PkgVerifyScript). PkgVerifyBody documents the
// shape; pkgverify_test.go runs both over one fixture and compares.

package script

import (
	"fmt"
	"slices"
	"strings"

	"karma/internal/section"
	"karma/internal/textutil"
)

// VerifyFacts is what one changed file is to the verify body: Key marks the
// files the body names individually (an ELF object, an executable, a
// conffile), Missing one that is gone rather than modified.
type VerifyFacts struct {
	Key     bool
	Missing bool
}

// PkgVerifyScript is the ssh and ttyd channels' package-verify tier for one
// verifier command (dpkg -V, rpm -Va). It builds the same body PkgVerifyBody
// renders, from the target's own file(1) and ls -l: the verifier's output
// tagged V, the types tagged F, the attributes tagged L, all read by one awk
// pass, so the classification and the grouping need no temporary file. A
// missing verifier exits 127 and the chain falls to the other package
// manager's tier; a clean verification is an empty answer.

// pkgVerifyAwk is the one pass that classifies and groups, the mirror of
// PkgVerifyBody: the thresholds and the section titles come from the constants
// above so the two bodies cannot drift apart. The stream it reads is tagged —
// V verifier line, F `path: type` from file(1), L an ls -l row — and every
// input line is held until the whole stream is read, because a group's size is
// only known once all of it is in. The program text carries no shell quotes:
// PkgVerifyScript wraps it, and runs it under LC_ALL=C so its string
// comparisons are the byte order the local channel sorts and groups by.
//
// The two sections keep the order their sources printed: `== file` follows the
// verifier's own order (file(1) reads its arguments in order, and
// localfs.FileRows renders the list it is handed without sorting), while `== ls`
// is path-sorted by ls itself and by localfs.LsRows. Sorting the file rows here
// would put the two channels' sections in different orders.

// The mass and listing thresholds, and the two section titles. PkgVerifyScript
// spells the same numbers in its awk program.
const (
	verifyMassFiles    = 20
	verifyListedFiles  = 3
	verifyKeyTitle     = section.Marker + "executables, libraries and conffiles"
	verifyOtherTitle   = section.Marker + "other changed files (grouped by directory)"
	verifyFilesSection = section.Marker + "file"
	verifyLsSection    = section.Marker + "ls"
)

// VerifyRow is one verifier line split into the parts the body groups by: dpkg
// -V and rpm -Va print a flag field, an optional conffile marker, and the path
// as the last word.
type VerifyRow struct {
	Line   string
	Path   string
	Prefix string
	Dir    string
}

// SplitVerifyRow splits one verifier line; the path is the last word, so a
// line without one (a package manager's own note) carries the whole line as
// its path and no directory.
func SplitVerifyRow(line string) VerifyRow {
	path := line
	if cut := strings.LastIndexByte(line, ' '); cut >= 0 {
		path = line[cut+1:]
	}
	row := VerifyRow{Line: line, Path: path, Prefix: line[:len(line)-len(path)]}
	if cut := strings.LastIndexByte(path, '/'); cut > 0 {
		row.Dir = path[:cut]
	}
	return row
}

// Conffile reports whether the verifier marked the row's file as a conffile:
// dpkg and rpm print a lone c between the flag field and the path.
func (r VerifyRow) Conffile() bool {
	return strings.HasSuffix(strings.TrimRight(r.Prefix, " \t"), " c")
}

// PkgVerifyBody renders the body of the package-verify check from the
// verifier's own output. classify says what one path is, and forensics renders
// the `== file` and `== ls` bodies for the paths the body names individually —
// the local channel answers both from the filesystem in process, a remote tier
// from file(1) and ls -l. A nil forensics renders no sections.
//
// The shape, in output order: the named rows verbatim, their forensics, then
// the other changed files — those whose directory holds few enough rows to
// list one by one, then one counted row per directory, in path order.
func PkgVerifyBody(verify string, classify func(path string) VerifyFacts, forensics func(paths []string) (files, ls string)) string {
	rows := parseVerify(verify)
	if len(rows) == 0 {
		return ""
	}
	facts := map[string]VerifyFacts{}
	for _, row := range rows {
		if _, seen := facts[row.Path]; !seen {
			facts[row.Path] = classify(row.Path)
		}
	}

	mass := subtreeCounts(rows)
	// A row is named individually when the verifier flagged a conffile or the
	// file is a program; the rest is counted under its directory, and the
	// leader decision is made once per row because the group sizes need it too.
	leader := make([]string, len(rows))
	kept := make([]bool, len(rows))
	sizes := map[string]int{}
	other := 0
	for index, row := range rows {
		if row.Conffile() || facts[row.Path].Key {
			kept[index] = true
			continue
		}
		other++
		leader[index] = massLeader(mass, row.Dir)
		if leader[index] != "" {
			sizes[leader[index]]++
		}
	}

	named := namedPaths(rows, facts)
	var filesBody, lsBody string
	if forensics != nil && len(named) > 0 {
		filesBody, lsBody = forensics(named)
	}

	var b strings.Builder
	if other < len(rows) {
		b.WriteString(verifyKeyTitle + "\n")
		for index, row := range rows {
			if kept[index] {
				b.WriteString(row.Line + missingNote(facts, row.Path) + "\n")
			}
		}
	}
	if filesBody != "" {
		b.WriteString(verifyFilesSection + "\n" + filesBody)
	}
	if lsBody != "" {
		b.WriteString(verifyLsSection + "\n" + lsBody)
	}
	if other == 0 {
		return b.String()
	}
	b.WriteString(verifyOtherTitle + "\n")

	type group struct {
		prefix  string
		count   int
		missing int
	}
	groups := map[string]*group{}
	var order []string
	for index, row := range rows {
		if kept[index] {
			continue
		}
		dir := leader[index]
		if dir == "" || sizes[dir] <= verifyListedFiles {
			b.WriteString(row.Line + missingNote(facts, row.Path) + "\n")
			continue
		}
		entry, seen := groups[dir]
		if !seen {
			entry = &group{prefix: row.Prefix}
			groups[dir] = entry
			order = append(order, dir)
		}
		entry.count++
		if facts[row.Path].Missing {
			entry.missing++
		}
	}
	slices.Sort(order)
	for _, dir := range order {
		entry := groups[dir]
		b.WriteString(fmt.Sprintf("%s%s/  %d files%s\n", entry.prefix, dir, entry.count, groupNote(entry.count, entry.missing)))
	}
	return b.String()
}

// missingNote marks a named row whose file is gone: neither dpkg's nor rpm's
// flag field says whether a file was modified or deleted, and the analyst needs
// that distinction on the row itself — a named row is the only evidence a
// directory too small to summarize leaves behind.
func missingNote(facts map[string]VerifyFacts, path string) string {
	if facts[path].Missing {
		return " (missing)"
	}
	return ""
}

// namedPaths lists the paths the body names individually — the conffile rows
// and the key files — in the order the verifier printed them.
func namedPaths(rows []VerifyRow, facts map[string]VerifyFacts) []string {
	var paths []string
	seen := map[string]bool{}
	for _, row := range rows {
		if row.Conffile() || facts[row.Path].Key {
			if !seen[row.Path] {
				seen[row.Path] = true
				paths = append(paths, row.Path)
			}
		}
	}
	return paths
}

// parseVerify splits the verifier's output into rows, dropping blank lines.
func parseVerify(verify string) []VerifyRow {
	var rows []VerifyRow
	for line := range textutil.Lines(verify) {
		if line == "" {
			continue
		}
		rows = append(rows, SplitVerifyRow(line))
	}
	return rows
}

// groupNote says what the counted files are: all gone, some gone, or all
// differing from the package db.
func groupNote(count, missing int) string {
	switch {
	case missing == count:
		return " missing"
	case missing > 0:
		return fmt.Sprintf(" differ, %d missing", missing)
	}
	return " differ"
}

// subtreeCounts counts the verifier rows under every directory prefix of every
// path, so a directory's mass is known from the file names alone.
func subtreeCounts(rows []VerifyRow) map[string]int {
	counts := map[string]int{}
	for _, row := range rows {
		for dir := row.Dir; dir != ""; dir = parentDir(dir) {
			counts[dir]++
		}
	}
	return counts
}

// massLeader is the deepest ancestor of dir that carries more than
// verifyMassFiles rows: a lone file below a mass is counted with that ancestor
// rather than named, and a directory with its own mass keeps its name. Empty
// means the path has no directory to be counted under.
func massLeader(mass map[string]int, dir string) string {
	if dir == "" {
		return ""
	}
	for leader := dir; leader != ""; leader = parentDir(leader) {
		if mass[leader] > verifyMassFiles {
			return leader
		}
	}
	return dir
}

// parentDir strips one path component; a path with no slash has no parent.
func parentDir(dir string) string {
	if cut := strings.LastIndexByte(dir, '/'); cut > 0 {
		return dir[:cut]
	}
	return ""
}
