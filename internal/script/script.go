// Package script builds the fragments the collection speaks in: the `^== `
// section header (reader cuts it into Sections, and each source is filtered and
// counted independently), shell word quoting for the collector's command line,
// the ls -l row shape (LSBodyPrintf, with SplitLsBody and AlignLsBodies in
// lsbody.go) that the listings print and the reading side reads, and the joins
// that turn this catalog's own marked record streams into rows.
package script

import (
	"regexp"
	"slices"
	"strings"

	"github.com/samber/lo"
)

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
// this, so both channels show one order.
func LsSorted(paths []string) []string {
	sorted := slices.Clone(paths)
	slices.Sort(sorted)
	return sorted
}
