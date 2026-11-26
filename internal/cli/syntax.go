// The content view: on a terminal, the built-in reader paints the file body
// with the format's own shape — shell and PowerShell scripts, ssh daemons and
// clients, and key/value configuration. A pipe still gets the raw bytes, so
// the reader stays scriptable. The palette is the report's: comments muted,
// keywords magenta, strings blue, variables cyan. The lexing is line-shaped
// and deliberately small; an unrecognized file prints untouched.

package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"unicode/utf8"

	chrome "karma/internal/panel"
)

// syntaxKind is one recognized content format.
type syntaxKind int

const (
	syntaxPlain syntaxKind = iota
	syntaxShell
	syntaxPowerShell
	syntaxSSH
	syntaxINI
)

// highlightContent returns the file's body with its syntax hues when the
// format is recognized and the stream is a terminal.
func highlightContent(path string, data []byte, color bool) []byte {
	if !color || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return data
	}
	kind := syntaxKindFor(path, data)
	if kind == syntaxPlain {
		return data
	}
	lines := strings.Split(string(data), "\n")
	for index, line := range lines {
		lines[index] = paintLine(kind, line)
	}
	return []byte(strings.Join(lines, "\n"))
}

// syntaxKindFor picks the format by the file's name, extension and first line.
func syntaxKindFor(path string, data []byte) syntaxKind {
	base := filepath.Base(path)
	if base == "sshd_config" || base == "ssh_config" ||
		strings.Contains(path, "/sshd_config.d/") || strings.Contains(path, "/ssh_config.d/") {
		return syntaxSSH
	}
	switch filepath.Ext(path) {
	case ".sh", ".bash", ".zsh":
		return syntaxShell
	case ".ps1":
		return syntaxPowerShell
	}
	if first := firstLine(data); strings.HasPrefix(first, "#!") {
		switch {
		case strings.Contains(first, "pwsh"), strings.Contains(first, "powershell"):
			return syntaxPowerShell
		case strings.Contains(first, "bash"), strings.Contains(first, "zsh"),
			strings.Contains(first, "dash"), strings.HasSuffix(strings.TrimSpace(first), "/sh"):
			return syntaxShell
		}
	}
	if looksLikeConfig(data) {
		return syntaxINI
	}
	return syntaxPlain
}

func firstLine(data []byte) string {
	if at := bytes.IndexByte(data, '\n'); at >= 0 {
		return string(data[:at])
	}
	return string(data)
}

// looksLikeConfig recognizes the key/value shape (an INI section or a
// KEY=VALUE line in the first screenful).
func looksLikeConfig(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n")[:min(20, strings.Count(string(data), "\n")+1)] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			return true
		}
		key, _, ok := strings.Cut(line, "=")
		if ok && key != "" && !strings.ContainsAny(key, " \t") {
			return true
		}
	}
	return false
}

// paintLine dispatches one line to its format's painter.
func paintLine(kind syntaxKind, line string) string {
	switch kind {
	case syntaxShell:
		return paintShellLine(line)
	case syntaxPowerShell:
		return paintPowerShellLine(line)
	case syntaxSSH:
		return paintSSHLine(line)
	case syntaxINI:
		return paintINILine(line)
	}
	return line
}

var shellKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true,
	"for": true, "while": true, "until": true, "do": true, "done": true,
	"case": true, "esac": true, "in": true, "function": true,
	"export": true, "local": true, "readonly": true, "return": true, "exit": true,
	"set": true, "unset": true, "source": true, "shift": true, "trap": true,
	"break": true, "continue": true, "eval": true, "exec": true, "time": true,
}

var powerShellKeywords = map[string]bool{
	"if": true, "else": true, "elseif": true, "foreach": true, "for": true,
	"while": true, "do": true, "function": true, "param": true, "return": true,
	"throw": true, "try": true, "catch": true, "finally": true, "switch": true,
	"begin": true, "process": true, "end": true, "in": true,
}

// paintShellLine colors comments, keywords, strings and variables.
func paintShellLine(line string) string {
	return paintScriptLine(line, shellKeywords)
}

// paintPowerShellLine is the same line shape with PowerShell's keywords.
func paintPowerShellLine(line string) string {
	return paintScriptLine(line, powerShellKeywords)
}

// paintScriptLine scans one script line left to right: a quote opens a
// string, a $ names a variable, a # at a word boundary starts a comment, and
// a bare word is a keyword when the language says so.
func paintScriptLine(line string, keywords map[string]bool) string {
	var out strings.Builder
	for index := 0; index < len(line); {
		ch := line[index]
		switch {
		case ch == '\'' || ch == '"':
			end := scanQuote(line, index)
			out.WriteString(paintCode(4, false, line[index:end]))
			index = end
		case ch == '$':
			end := scanVariable(line, index)
			out.WriteString(paintCode(6, false, line[index:end]))
			index = end
		case ch == '#' && (index == 0 || line[index-1] == ' ' || line[index-1] == '\t'):
			out.WriteString(chrome.Paint(true, chrome.Fg(chrome.MutedColor), line[index:]))
			return out.String()
		case isWordStart(line, index):
			end := scanWord(line, index)
			word := line[index:end]
			if keywords[word] {
				out.WriteString(paintCode(5, false, word))
			} else {
				out.WriteString(word)
			}
			index = end
		default:
			out.WriteByte(ch)
			index++
		}
	}
	return out.String()
}

// scanQuote returns the end of the quoted run starting at index; an
// unterminated quote runs to the end of the line.
func scanQuote(line string, index int) int {
	quote := line[index]
	for at := index + 1; at < len(line); at++ {
		switch {
		case quote == '"' && line[at] == '\\':
			at++
		case line[at] == quote:
			return at + 1
		}
	}
	return len(line)
}

// scanVariable returns the end of $NAME, ${NAME} or $(...)-free references.
func scanVariable(line string, index int) int {
	at := index + 1
	if at >= len(line) {
		return at
	}
	if line[at] == '{' {
		if close := strings.IndexByte(line[at:], '}'); close >= 0 {
			return at + close + 1
		}
		return len(line)
	}
	for at < len(line) && (isWordByte(line[at])) {
		at++
	}
	return at
}

// isWordStart reports a word beginning at index: a word byte preceded by a
// non-word byte.
func isWordStart(line string, index int) bool {
	if !isWordByte(line[index]) {
		return false
	}
	return index == 0 || !isWordByte(line[index-1])
}

func isWordByte(ch byte) bool {
	return ch == '_' || ch == '-' || ch == '.' || ch == '/' ||
		ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
}

func scanWord(line string, index int) int {
	at := index
	for at < len(line) && isWordByte(line[at]) {
		at++
	}
	return at
}

// paintSSHLine colors the directive at the head of a sshd/ssh config line and
// any trailing comment.
func paintSSHLine(line string) string {
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" {
		return line
	}
	if strings.HasPrefix(trimmed, "#") {
		return chrome.Paint(true, chrome.Fg(chrome.MutedColor), line)
	}
	indent := line[:len(line)-len(trimmed)]
	at := strings.IndexAny(trimmed, " \t")
	if at < 0 {
		return indent + paintCode(5, false, trimmed)
	}
	word, rest := trimmed[:at], trimmed[at:]
	if comment := strings.Index(rest, " #"); comment >= 0 {
		return indent + paintCode(5, false, word) + paintCode(4, false, rest[:comment]) +
			chrome.Paint(true, chrome.Fg(chrome.MutedColor), rest[comment:])
	}
	return indent + paintCode(5, false, word) + rest
}

// paintINILine colors an INI/unit line: a section head, or a KEY=VALUE pair
// with a commented tail.
func paintINILine(line string) string {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
		return chrome.Paint(true, chrome.Fg(chrome.MutedColor), line)
	}
	indent := line[:len(line)-len(trimmed)]
	if strings.HasPrefix(trimmed, "[") {
		return indent + paintCode(5, true, trimmed)
	}
	key, value, ok := strings.Cut(trimmed, "=")
	if !ok || key == "" || strings.ContainsAny(key, " \t") {
		return line
	}
	painted := indent + paintCode(4, false, key) + "="
	if at := strings.Index(value, " #"); at >= 0 {
		return painted + value[:at] + chrome.Paint(true, chrome.Fg(chrome.MutedColor), value[at:])
	}
	return painted + value
}
