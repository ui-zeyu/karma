// Package script builds fragments of target-machine collection scripts: per-file
// reads and per-directory listing section loops. The `^== ` section header is the
// structural convention of collection output: reader cuts it into Sections and each
// source is filtered and counted independently. Shell word quoting also lives here
// (remote rendering and collection scripts share one escaping), and so does the
// ls -l body row both sides speak: LSBodyPrintf is the shape the collection
// prints, SplitLsBody and AlignLsBodies (lsbody.go) the reading side's view of it.
package script

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/samber/lo"
)

const wordsPerLine = 4 // word-list wrap width: matches the line-continuation style of existing scripts

// LSBodyPrintf is the ls -l row shape: permissions links owner group size date clock path.
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

// Lines joins script fragments into one multi-line script: the shared spelling of
// every per-section collection script.
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

// ReadFiles generates a per-file read for loop: one section per file (`== path`
// header), missing ones skipped. command is the read command for a single file,
// referencing the current file as $f; paths and globs are spliced verbatim into the
// word list and expanded by the target shell; quiet discards the read's standard error
// (files with insufficient permissions produce no noise, and unreadable facts are
// shown by an empty section).
func ReadFiles(paths []string, command string, quiet bool) string {
	redirect := ""
	if quiet {
		redirect = " 2>/dev/null"
	}
	return fmt.Sprintf("for f in %s; do\n  [ -f \"$f\" ] && { echo \"== $f\"; %s%s; }\ndone",
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
	rows := lo.Map(lo.Chunk(paths, wordsPerLine), func(row []string, _ int) string {
		return strings.Join(row, " ")
	})
	return strings.Join(rows, " \\\n         ")
}
