// The package-verify body: what changed, without the wall of text a slimmed
// image produces. A package db that disagrees with the image's documentation,
// locale and man files is noise the analyst has to scroll past to reach the two
// binaries that matter, so the body names the files that can be a finding — an
// ELF object, an executable, a conffile — one by one with their type and
// attributes, and counts the rest per directory, noting how many of them are
// gone rather than modified.
//
// The body carries four parts, in this order: the named rows, their type rows,
// their attribute rows, then the other changed files — the directories small
// enough to list one by one, then one counted row per directory. Each part opens
// with a label line, and PkgVerifyTitles names those labels so the check can
// declare them (model.Probe.Titles): the reading opens a section titled with each
// one, which is how one verifier run's four parts reach the report as four
// sections rather than as one flat block. A part with no rows prints nothing,
// label included.
//
// Two implementations render that body and must agree word for word: this
// file's Go side (PkgVerifyBody, the local channel) and the awk pipeline the
// sh source runs (PkgVerifyScript). PkgVerifyBody documents the
// shape; pkgverify_test.go runs both over one fixture and compares.

package script

import (
	"fmt"
	"slices"
	"strings"

	"karma/internal/textutil"
)

// VerifyFacts is what one changed file is to the verify body: Key marks the
// files the body names individually (an ELF object, an executable, a
// conffile), Missing one that is gone rather than modified.
type VerifyFacts struct {
	Key     bool
	Missing bool
}

// PkgVerifyScript is the sh source's package-verify tier for one
// verifier command (dpkg -V, rpm -Va). It builds the same body PkgVerifyBody
// renders, from the target's own file(1) and ls -l: the verifier's output
// tagged V, the types tagged F, the attributes tagged L, all read by one awk
// pass, so the classification and the grouping need no temporary file. A
// missing verifier exits 127 and the chain falls to the other package
// manager's tier; a clean verification is an empty answer.
func PkgVerifyScript(command string) string {
	binary, _, _ := strings.Cut(command, " ")
	return fmt.Sprintf(`command -v %[1]s >/dev/null 2>&1 || exit 127
verify=$(%[2]s 2>/dev/null)
[ -n "$verify" ] || exit 0
paths=$(printf '%%s\n' "$verify" | awk 'NF {print $NF}')
havefile=0
command -v file >/dev/null 2>&1 && havefile=1
{
  printf '%%s\n' "$verify" | sed 's/^/V /'
  [ "$havefile" = 1 ] && LC_ALL=C file $paths 2>/dev/null | sed 's/^/F /'
  LC_ALL=C ls -l $paths 2>/dev/null | sed 's/^/L /'
} | LC_ALL=C awk -v havefile=$havefile '%[3]s'
exit 0
`, binary, command, pkgVerifyAwk())
}

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
// would put the two sources' sections in different orders.
func pkgVerifyAwk() string {
	return fmt.Sprintf(`BEGIN { mass = %[1]d; listed = %[2]d }
{
  tag = substr($0, 1, 1); rest = substr($0, 3)
  if (tag == "V") {
    if (rest == "") next
    n++
    vline[n] = rest
    p = rest; sub(/.* /, "", p)
    vpath[n] = p
    vpre[n] = rest; sub(/[^ ]*$/, "", vpre[n])
    # the counted rows carry this field blank (blankField)
    vblank[n] = vpre[n]; gsub(/./, " ", vblank[n])
    if (vpre[n] ~ / c[ \t]*$/) conf[n] = 1
    d = p
    if (!sub("/[^/]*$", "", d)) d = ""
    vdir[n] = d
    a = d
    while (a != "") { tot[a]++; sub("/[^/]*$", "", a) }
    next
  }
  if (tag == "F") {
    fp = rest; sub(/:[ ]+.*$/, "", fp)
    if (rest ~ /No such file or directory/) { gone[fp] = 1; next }
    fn++
    fpath[fn] = fp
    fline[fn] = rest; sub(/:[ ]+/, ": ", fline[fn])
    ftype = substr(rest, length(fp) + 1); sub(/^:[ ]*/, "", ftype)
    if (ftype ~ /^ELF/ || ftype ~ /(^|[ ,])executable([ ,]|$)/) key[fp] = 1
    next
  }
  if (tag == "L") {
    ln++
    lline[ln] = rest
    nf = split(rest, f, /[ ]+/)
    p = f[9]; for (i = 10; i <= nf; i++) p = p " " f[i]
    sub(/ -> .*$/, "", p)
    lpath[ln] = p
    if (substr(f[1], 4, 1) ~ /[xsS]/) key[p] = 1
    next
  }
}
function dirkey(d,   a) {
  if (d == "") return ""
  a = d
  while (a != "") { if (tot[a] > mass) return a; sub("/[^/]*$", "", a) }
  return d
}
END {
  named = 0; other = 0
  for (i = 1; i <= n; i++) {
    if (conf[i] || key[vpath[i]]) { name[i] = 1; named = 1; namedpath[vpath[i]] = 1; continue }
    other = 1
    g = dirkey(vdir[i])
    gkey[i] = g
    if (g != "") gcount[g]++
  }
  if (named) print "%[3]s"
  for (i = 1; i <= n; i++) if (name[i]) print vline[i] (havefile && gone[vpath[i]] ? " (missing)" : "")
  # Both parts keep the order their source printed: the F rows the argument
  # order file(1) reads, the L rows the order ls sorted its arguments into. The
  # local channel renders them the same way, so nothing is re-ordered here.
  for (i = 1; i <= fn; i++) if (namedpath[fpath[i]] && !fseen[fpath[i]]) { if (!inf) { print "%[5]s"; inf = 1 }; fseen[fpath[i]] = 1; print fline[i] }
  for (i = 1; i <= ln; i++) if (namedpath[lpath[i]] && !lseen[lpath[i]]) { if (!inl) { print "%[6]s"; inl = 1 }; lseen[lpath[i]] = 1; print lline[i] }
  if (!other) exit
  print "%[4]s"
  for (i = 1; i <= n; i++) {
    if (name[i]) continue
    g = gkey[i]
    if (g == "" || gcount[g] <= listed) { print vline[i] (havefile && gone[vpath[i]] ? " (missing)" : ""); continue }
    if (!(g in seen)) { seen[g] = 1; gtot[g] = 0; gblank[g] = vblank[i] }
    gtot[g]++
    if (gone[vpath[i]]) gmiss[g]++
    if (!(g in listed_group)) { listed_group[g] = 1; gorder[++gn] = g }
  }
  for (a = 2; a <= gn; a++) { g = gorder[a]; b = a - 1
    while (b >= 1 && gorder[b] > g) { gorder[b + 1] = gorder[b]; b-- }
    gorder[b + 1] = g }
  for (j = 1; j <= gn; j++) {
    g = gorder[j]
    if (!havefile) print gblank[g] g "/  " gtot[g] " files"
    else if (gmiss[g] == gtot[g]) print gblank[g] g "/  " gtot[g] " files missing"
    else if (gmiss[g] > 0) print gblank[g] g "/  " gtot[g] " files differ, " gmiss[g] " missing"
    else print gblank[g] g "/  " gtot[g] " files differ"
  }
}`, verifyMassFiles, verifyListedFiles, verifyKeyLabel, verifyOtherLabel, verifyFilesLabel, verifyLsLabel)
}

// The mass and listing thresholds, and the labels the body prints in front of
// its parts. PkgVerifyScript spells the same numbers and the same labels in its
// awk program.
const (
	verifyMassFiles   = 20
	verifyListedFiles = 3
	verifyKeyLabel    = "executables, libraries and conffiles"
	verifyFilesLabel  = "file"
	verifyLsLabel     = "ls"
	verifyOtherLabel  = "other changed files (grouped by directory)"
)

// PkgVerifyTitles are the body's part labels in output order. The check declares
// them (model.Probe.Titles) on both sources' tiers, so the reading opens a
// section titled with each one; the body prints a label only in front of rows it
// has, so a part with nothing to show states nothing.
var PkgVerifyTitles = []string{verifyKeyLabel, verifyFilesLabel, verifyLsLabel, verifyOtherLabel}

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
// the type and attribute bodies for the paths the body names individually —
// the local channel answers both from the filesystem in process, a remote tier
// from file(1) and ls -l. A nil forensics renders neither.
//
// The shape, in output order: the named rows verbatim, their type and attribute
// rows, then the other changed files — those whose directory holds few enough
// rows to list one by one, then one counted row per directory, in path order. A
// counted row states the directory and how many files it counts, with the flag
// field left blank: the count is the row's evidence, and one member's flags are
// not. Each part follows its own label line (PkgVerifyTitles), and a part with no
// rows prints nothing at all, label included.
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
	// Each part opens with its own label: the parts are one section because they
	// share the verifier run, so the label is the only thing that says what the
	// rows under it are. No blank line separates them — the reading layer drops
	// blank rows on every check — so the label is the separation.
	if other < len(rows) {
		b.WriteString(verifyKeyLabel + "\n")
		for index, row := range rows {
			if kept[index] {
				b.WriteString(row.Line + missingNote(facts, row.Path) + "\n")
			}
		}
	}
	if filesBody != "" {
		b.WriteString(verifyFilesLabel + "\n" + filesBody)
	}
	if lsBody != "" {
		b.WriteString(verifyLsLabel + "\n" + lsBody)
	}
	if other == 0 {
		return b.String()
	}
	b.WriteString(verifyOtherLabel + "\n")

	type group struct {
		blank   string
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
			entry = &group{blank: blankField(row.Prefix)}
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
		b.WriteString(fmt.Sprintf("%s%s/  %d files%s\n",
			entry.blank, dir, entry.count, groupNote(entry.count, entry.missing)))
	}
	return b.String()
}

// blankField is the flag field a counted row carries: as wide as the verifier
// prints its own, and empty. The counted row is a directory's count rather than
// a file, so the flags of whichever member happened to open the group say
// nothing about the rest of it — and the check's rule for the verifier's own
// rows would otherwise read a count as one file's verdict, which is what makes
// a wall of them all say the same thing.
func blankField(prefix string) string {
	return strings.Repeat(" ", len(prefix))
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
