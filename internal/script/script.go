// Package script builds the fragments the sh source speaks in: shell word
// quoting for the pinned spellings and the bootstrap command line, the ls -l row
// shape (LSBodyPrintf, with SplitLsBody and AlignLsBodies in lsbody.go) that the
// listings print and the reading side reads, the file-list and directory-list
// calls the sh source runs where karma's own body cannot, and the joins that turn
// this catalog's own marked record streams into rows.
//
// Sections are not this package's: a section boundary is the collection's own
// statement (model.BodySection), so the sh source names its sections by
// declaring one call per section rather than by printing a header its reader
// would have to recognize.
package script

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/samber/lo"
)

const wordsPerLine = 4 // word-list wrap width: matches the line-continuation style of existing scripts

// ProcPrefix is what every /proc link path starts with and no report prints.
const ProcPrefix = "/proc/"

// DeletedLinkRow renders one row of the deleted-file check: the link path with
// the /proc prefix cut, then the target the kernel annotated.
func DeletedLinkRow(link, target string) string {
	return strings.TrimPrefix(link, ProcPrefix) + " -> " + target
}

// LSBodyPrintf is the ls -l row shape: permissions links owner group size date
// clock path. A symlink row appends its target with no arrow (find's %l prints
// the target alone); the reading side separates path and target.
const LSBodyPrintf = `%M %n %u %g %s %Tb %Td %TH:%TM %p%l\n`

// ListingPrintf is the directory listing collection row: epoch mtime, epoch ctime
// lead; cluster uses them to cluster, and the prefix is stripped before display.
const ListingPrintf = `%T@\t%C@\t` + LSBodyPrintf

var unsafeShellChar = regexp.MustCompile(`[^A-Za-z0-9_@%+=:,./-]`)

// shellReserved are POSIX shell reserved words: bare in a word position they
// would read as syntax (a directory named "done" inside a for list breaks the
// loop), so Quote quotes them like unsafe characters.
var shellReserved = map[string]bool{
	"do": true, "done": true, "elif": true, "else": true, "esac": true,
	"fi": true, "for": true, "if": true, "in": true, "then": true,
	"until": true, "while": true,
}

// Lines joins script fragments into one multi-line script.
func Lines(parts ...string) string {
	return strings.Join(parts, "\n")
}

// Join renders words into a shell word string: only unsafe characters get single quotes.
func Join(argv []string) string {
	return strings.Join(lo.Map(argv, func(word string, _ int) string { return Quote(word) }), " ")
}

// Quote is shell escaping for a single word: wrap in single quotes, closing and
// reopening around embedded single quotes. A reserved word gets the same
// treatment: bare, it would read as syntax rather than a name.
func Quote(word string) string {
	if word == "" {
		return "''"
	}
	if unsafeShellChar.MatchString(word) || shellReserved[word] {
		return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
	}
	return word
}

// LsSorted sorts paths the way the collection's `LC_ALL=C ls -l` prints its
// arguments: by the argument string, byte for byte. A tier that renders the
// same list in process (the miner's drop paths and temp-name hits) sorts with
// this, so both sources show one order.
func LsSorted(paths []string) []string {
	sorted := slices.Clone(paths)
	slices.Sort(sorted)
	return sorted
}

// ReadFile builds the per-file call of a file-list tier: the current file bound
// to f, then the read command the tier pins, with the read's own error text
// dropped (files with insufficient permissions produce no noise, and unreadable
// facts are shown by an empty section). The command references the file as $f,
// the same spelling the per-file loop used.
func ReadFile(path, command string) string {
	return "f=" + Quote(path) + "; " + command + " 2>/dev/null"
}

// ListFiles is a file list's own answer: the existing regular files of a path and
// glob word list, one path per line, in the order the per-file loop read them.
// paths and globs are spliced verbatim into the word list and expanded by the
// target shell.
func ListFiles(paths []string) string {
	return fmt.Sprintf("for f in %s; do\n  [ -f \"$f\" ] && echo \"$f\"\ndone", WordList(paths))
}

// ListDirs is a directory list's own answer: the words the list names, one path
// per line, globs expanded by the target shell. A word that names nothing still
// answers with itself, and its (empty) section body is dropped by the reading
// layer, the same way the find pipeline's own silence is.
func ListDirs(dirs []string) string {
	return fmt.Sprintf("for d in %s; do\n  echo \"$d\"\ndone", WordList(dirs))
}

// ListingFind is the collection row for a single directory: the directory expression
// is always quoted, sorted by mtime descending and then capped by head. LC_ALL=C pins
// %Tb's month name to English: the ls-l row shape does not drift with the target's
// locale (under a localized locale %Tb emits a localized month name and the row shape
// falls apart).
func ListingFind(dirExpr string, head int) string {
	return fmt.Sprintf("LC_ALL=C find \"%s\" -maxdepth 1 -mindepth 1 -printf '%s' 2>/dev/null | sort -rn | head -n %d",
		dirExpr, ListingPrintf, head)
}

// WordList wraps the word list: globs must stay unescaped, and continuations use backslashes.
func WordList(paths []string) string {
	rows := slices.Collect(slices.Chunk(paths, wordsPerLine))
	lines := make([]string, len(rows))
	for i, row := range rows {
		lines[i] = strings.Join(row, " ")
	}
	return strings.Join(lines, " \\\n         ")
}
