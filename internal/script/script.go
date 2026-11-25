// Package script builds the fragments the shell speaks in: word quoting and the
// ls -l row shape
// (LSBodyPrintf, with SplitLsBody and AlignLsBodies in lsbody.go) that the
// built-in listing prints.
package script

import (
	"regexp"
	"strings"

	"github.com/samber/lo"
)

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
