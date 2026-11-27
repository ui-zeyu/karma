package audit

import (
	"os"
	"strings"

	chrome "karma/internal/panel"
)

// highlightTokens paints the object and verdict tokens inside one prose
// line: a path keeps the information hue and an origin word keeps its
// temporal hue, while the sentence around them stays in base. An origin word
// is recognised only where a parenthesized explanation follows it
// ("runtime (created ...)"), the shape the judges write.
func highlightTokens(text string, base int, color bool) string {
	text = chrome.SafeText(text)
	if !color || text == "" {
		return text
	}
	paintBase := func(segment string) string {
		if base == 0 {
			return segment
		}
		return chrome.Paint(true, chrome.Fg(base), segment)
	}
	var out strings.Builder
	for index := 0; index < len(text); {
		if text[index] == ' ' {
			end := index
			for end < len(text) && text[end] == ' ' {
				end++
			}
			out.WriteString(paintBase(text[index:end]))
			index = end
			continue
		}
		end := index
		for end < len(text) && text[end] != ' ' {
			end++
		}
		token := text[index:end]
		prefix, core, suffix, isPath := pathToken(token)
		if !isPath {
			core, suffix = trimToken(token)
		}
		origin, known := originByName(core)
		switch {
		case isPath:
			out.WriteString(paintBase(prefix))
			out.WriteString(chrome.Paint(true, chrome.Fg(hueInformation), core))
			out.WriteString(paintBase(suffix))
		case known && parenFollows(text, end):
			out.WriteString(chrome.Paint(true, chrome.Fg(originHue(origin)), core))
			out.WriteString(paintBase(suffix))
		default:
			out.WriteString(paintBase(token))
		}
		index = end
	}
	return out.String()
}

// pathToken splits a token that carries an absolute path. A path starts the
// token or follows an assignment/opening delimiter, so a URL's `//` and a
// relative `dir/file` stay plain. The prefix and suffix keep their base paint.
func pathToken(token string) (prefix, core, suffix string, ok bool) {
	if strings.HasPrefix(token, "/") {
		core, suffix = trimToken(token)
		return "", core, suffix, len(core) > 1
	}
	for index := 1; index < len(token); index++ {
		if token[index] != '/' {
			continue
		}
		switch token[index-1] {
		case '=', '(', '"', '\'', '[':
		default:
			continue
		}
		core, suffix = trimToken(token[index:])
		if len(core) > 1 {
			return token[:index], core, suffix, true
		}
	}
	return "", "", "", false
}

// trimToken splits the punctuation a prose token may carry after its core.
func trimToken(token string) (core, suffix string) {
	end := len(token)
	for end > 0 && strings.ContainsRune(",.:;)]}\"'", rune(token[end-1])) {
		end--
	}
	return token[:end], token[end:]
}

// parenFollows reports whether the next non-space character opens the
// explanation the origin slot carries.
func parenFollows(text string, index int) bool {
	for index < len(text) && text[index] == ' ' {
		index++
	}
	return index < len(text) && text[index] == '('
}

// originByName reads an origin word back to its value.
func originByName(name string) (Origin, bool) {
	for index, candidate := range originNames {
		if candidate == name {
			return Origin(index), true
		}
	}
	return Unknown, false
}

func padRight(text string, width int) string {
	if n := chrome.DisplayWidth(text); n < width {
		return text + strings.Repeat(" ", width-n)
	}
	return text
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func selfPID() int { return os.Getpid() }
