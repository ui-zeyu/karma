package script

import (
	"strings"
	"testing"
)

// sep is the splice Quote writes for one embedded single quote: close the
// chunk, a backslash-escaped quote, reopen.
const sep = "'" + `\` + "'" + "'"

// unquotePosix evaluates the only shapes Quote emits: a bare run of safe
// characters, or single-quoted chunks joined by sep. Anything else fails the
// parse, so the property also pins the output shape.
func unquotePosix(quoted string) (string, bool) {
	if quoted == "" {
		return "", false
	}
	if !strings.HasPrefix(quoted, "'") {
		// bare branch: the whole word is one run of safe characters
		if strings.IndexByte(quoted, '\'') >= 0 {
			return "", false
		}
		return quoted, true
	}
	var out strings.Builder
	quoted = quoted[1:]
	for {
		end := strings.IndexByte(quoted, '\'')
		if end < 0 {
			return "", false
		}
		out.WriteString(quoted[:end])
		quoted = quoted[end:]
		if !strings.HasPrefix(quoted, sep) {
			// the quote is the final close; nothing may follow it
			quoted = quoted[1:]
			if quoted != "" {
				return "", false
			}
			return out.String(), true
		}
		quoted = quoted[len(sep):]
		out.WriteByte('\'')
	}
}

func FuzzQuote(f *testing.F) {
	f.Add("")
	f.Add("done")
	f.Add("/etc/passwd")
	f.Add("it's")
	f.Add("$(reboot); rm -rf /")
	f.Add("sp ace")
	f.Fuzz(func(t *testing.T, word string) {
		quoted := Quote(word)
		parsed, ok := unquotePosix(quoted)
		if !ok || parsed != word {
			t.Fatalf("Quote(%q) = %q re-parses to (%q, %v)", word, quoted, parsed, ok)
		}
		if shellReserved[word] && quoted != "'"+word+"'" {
			t.Fatalf("reserved word %q must come out quoted: %q", word, quoted)
		}
	})
}
