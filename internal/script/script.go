// Package script builds the fragments the collection speaks in: the `== `
// section header the loops below echo (internal/section owns the convention, and
// the reader cuts on it so every section is filtered and counted on its own),
// shell word quoting for the pinned spellings and the bootstrap command line,
// the ls -l row shape (LSBodyPrintf, with SplitLsBody and AlignLsBodies in
// lsbody.go) that the listings print and the reading side reads, the per-file
// read and per-directory listing loops the sh source runs where karma's own
// body cannot, and the joins that turn this catalog's own marked record streams
// into rows.
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

// ReadFiles generates a per-file read for loop: one section per file (`== path`
// header), missing ones skipped. command is the read command for a single file,
// referencing the current file as $f; paths and globs are spliced verbatim into the
// word list and expanded by the target shell; quiet discards the read's standard error
// (files with insufficient permissions produce no noise, and unreadable facts are
// shown by an empty section).
//
// The body is piped through `awk '{print}'`, which terminates a file whose last
// line carries no newline. Without it the next `== path` header glues onto that
// line and the section loses its title and its own body. awk rather than sed:
// GNU sed's `-n p` adds the missing newline but BSD sed passes the line through
// unchanged (both engines of awk terminate it). localfs.ReadSections gives the
// in-process tier the same guarantee.
func ReadFiles(paths []string, command string, quiet bool) string {
	redirect := ""
	if quiet {
		redirect = " 2>/dev/null"
	}
	return fmt.Sprintf("for f in %s; do\n  [ -f \"$f\" ] && { echo \"== $f\"; %s%s | awk '{print}'; }\ndone",
		WordList(paths), command, redirect)
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

// ListingSections is the per-directory sectioned collection script: one section per
// directory `== $d`, with the line count capped uniformly by head. The directory word
// list is spliced verbatim and globs are expanded by the target shell; when a
// directory does not exist the section body is empty and dropped by the reading
// layer. The remote head is the line cap: the script caps itself, so the probe need
// not carry a line cap to align.
func ListingSections(dirs []string, head int) string {
	lines := []string{
		"for d in " + strings.Join(dirs, " ") + "; do",
		`  echo "== $d"`,
		"  " + ListingFind("$d", head),
		"done",
	}
	return strings.Join(lines, "\n")
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
