// Package panel is the hand-drawn chrome the report and the command-line help
// screens share: the two heading bands, the rail panel, and the text
// primitives the rail wraps with. The palette and the rail's shape live here
// once; audit's report and cli's help are the two compositions.
package panel

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Byline is the band's right edge: the operator's name when the environment
// carries one, the tool's own name otherwise. The report's masthead and the
// command pages share it.
func Byline() string {
	if user := os.Getenv("USER"); user != "" {
		return SafeText(user) + " "
	}
	return "karma "
}

// The report's chrome palette: a dark level-one band, a lighter level-two
// band, and muted grey. Severity hues stay with the report.
const (
	BannerBG   = 236
	BannerFG   = 15
	SubBandBG  = 238
	SubBandFG  = 250
	MutedColor = 244
	Reset      = "\x1b[0m"
)

// Fg is a 256-color foreground sequence.
func Fg(code int) string { return fmt.Sprintf("\x1b[38;5;%dm", code) }

// Bg is a 256-color background sequence.
func Bg(code int) string { return fmt.Sprintf("\x1b[48;5;%dm", code) }

// Paint wraps text in codes; color off passes the text through.
func Paint(color bool, codes, text string) string {
	if !color || codes == "" {
		return text
	}
	return codes + text + Reset
}

// Band fills one line: the label on the left, the metadata on the right.
func Band(left, right string, width, bgCode, fgCode int, bold, color bool) string {
	if width < 8 {
		width = 8
	}
	if DisplayWidth(left)+DisplayWidth(right) > width {
		right = ""
		left = Truncate(left, width)
	}
	fill := width - DisplayWidth(left) - DisplayWidth(right)
	if fill < 0 {
		fill = 0
	}
	plain := left + strings.Repeat(" ", fill) + right
	if !color {
		return strings.TrimRight(plain, " ")
	}
	style := Bg(bgCode) + Fg(fgCode)
	if bold {
		style += "\x1b[1m"
	}
	return style + plain + Reset
}

// Rail draws one panel: a half-block rail in the rail color, a filled head
// band, and body rows indented two columns. A table row hard-wraps at the
// width, so its columns stay aligned.
func Rail(head string, body []string, width, railColor int, color bool) string {
	return rail(head, body, width, railColor, color, Wrap)
}

// RailText draws a panel whose body is prose: every row word-wraps with a
// two-column hanging indent. Use Rail for aligned tables; the two functions
// make the wrap choice explicit at the call site.
func RailText(head string, body []string, width, railColor int, color bool) string {
	return rail(head, body, width, railColor, color, func(line string, inner int) []string {
		return WrapProse(line, inner, 2)
	})
}

func rail(head string, body []string, width, railColor int, color bool, wrap func(string, int) []string) string {
	inner := width - 4
	lines := []string{head}
	for _, line := range body {
		line = strings.TrimRight(line, " ")
		for _, wrapped := range wrap(line, inner) {
			lines = append(lines, "  "+wrapped)
		}
	}
	prefix := Paint(color, Fg(railColor), "▌")
	var out strings.Builder
	for _, line := range lines {
		out.WriteString(prefix)
		out.WriteString(line)
		out.WriteString("\n")
	}
	return strings.TrimRight(out.String(), "\n")
}

// Wrap breaks a body line inside a panel: between words first, then by
// character only when one token is wider than the line. A line carrying runs
// of spaces (a table row) is hard-wrapped instead, which keeps columns aligned.
// Painted lines keep their colors across the break: each continuation line
// re-opens the SGR state it started under.
func Wrap(text string, width int) []string {
	if width < 8 {
		width = 8
	}
	if DisplayWidth(text) <= width {
		return []string{text}
	}
	runes := styledRunes(text)
	if strings.Contains(StripANSI(text), "  ") {
		return wrapHard(runes, width)
	}
	return wrapWords(runes, width)
}

// WrapProse wraps a prose line at word boundaries, indenting every
// continuation line by hang columns. A token wider than the line is hard-cut
// like Wrap's fallback; painted lines re-open their SGR state per line.
func WrapProse(text string, width, hang int) []string {
	if width < 8 {
		width = 8
	}
	if DisplayWidth(text) <= width {
		return []string{text}
	}
	runes := styledRunes(text)
	bindStyledTimestamps(runes)
	var lines []string
	first := true
	clean := func(line string) string { return strings.ReplaceAll(line, "\u00a0", " ") }
	for len(runes) > 0 {
		budget, prefix := width, ""
		if !first {
			budget = width - hang
			if budget < 1 {
				budget = 1
			}
			prefix = strings.Repeat(" ", hang)
		}
		if len(runes) <= budget {
			lines = append(lines, clean(prefix+renderStyled(runes)))
			return lines
		}
		cut := budget
		for index := budget; index > 0; index-- {
			if runes[index].r == ' ' {
				cut = index
				break
			}
		}
		lines = append(lines, clean(prefix+renderStyled(runes[:cut])))
		runes = runes[cut:]
		for len(runes) > 0 && runes[0].r == ' ' {
			runes = runes[1:]
		}
		first = false
	}
	return lines
}

// dateClock is the report's timestamp shape. A reader treats the date and the
// clock as one fact, so WrapProse binds their separator with a non-breaking
// mark and turns it back into a space after the line is cut.
var dateClock = regexp.MustCompile(`\b(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\b`)

// bindStyledTimestamps applies the binding to the visible runes: an evidence
// line paints the date and the clock as separate tokens, so a regex over the
// raw string would stop at the SGR sequences between them.
func bindStyledTimestamps(runes []styledRune) {
	var plain strings.Builder
	for _, styled := range runes {
		plain.WriteRune(styled.r)
	}
	bound := []rune(bindTimestamps(plain.String()))
	if len(bound) != len(runes) {
		return
	}
	for index := range runes {
		if bound[index] == '\u00a0' {
			runes[index].r = '\u00a0'
		}
	}
}

func bindTimestamps(text string) string {
	return dateClock.ReplaceAllString(text, "$1\u00a0$2")
}

// styledRune is one visible rune and the SGR state it is printed under: the
// sequences open at that point, which a wrapped continuation line re-emits.
type styledRune struct {
	r     rune
	state string
}

// styledRunes reads a painted line into visible runes, folding every SGR
// sequence into the state of the runes that follow it.
func styledRunes(text string) []styledRune {
	out := make([]styledRune, 0, len(text))
	state := ""
	for index := 0; index < len(text); {
		if text[index] == 0x1b {
			end := escapeEnd(text, index)
			sequence := text[index:end]
			if strings.HasSuffix(sequence, "m") {
				if sequence == Reset || sequence == "\x1b[m" {
					state = ""
				} else {
					state += sequence
				}
			}
			index = end
			continue
		}
		r, size := utf8.DecodeRuneInString(text[index:])
		out = append(out, styledRune{r: r, state: state})
		index += size
	}
	return out
}

// renderStyled writes the runes back, opening each state once and closing the
// last one, so every line is self-contained.
func renderStyled(runes []styledRune) string {
	var out strings.Builder
	open := ""
	for _, styled := range runes {
		if styled.state != open {
			if open != "" {
				out.WriteString(Reset)
			}
			if styled.state != "" {
				out.WriteString(styled.state)
			}
			open = styled.state
		}
		out.WriteRune(styled.r)
	}
	if open != "" {
		out.WriteString(Reset)
	}
	return out.String()
}

// wrapHard cuts at the line width, keeping a table row's columns in place.
func wrapHard(runes []styledRune, width int) []string {
	var lines []string
	for len(runes) > width {
		lines = append(lines, renderStyled(runes[:width]))
		runes = runes[width:]
	}
	return append(lines, renderStyled(runes))
}

// wrapWords breaks at the last space before the line width, falling back to a
// hard cut inside a token wider than the line.
func wrapWords(runes []styledRune, width int) []string {
	var lines []string
	for len(runes) > 0 {
		if len(runes) <= width {
			return append(lines, renderStyled(runes))
		}
		cut := width
		for index := width; index > 0; index-- {
			if runes[index].r == ' ' {
				cut = index
				break
			}
		}
		lines = append(lines, renderStyled(runes[:cut]))
		runes = runes[cut:]
		for len(runes) > 0 && runes[0].r == ' ' {
			runes = runes[1:]
		}
	}
	return lines
}

// SafeText makes untrusted text safe for one terminal row. Host files and
// process argv can carry escape sequences, newlines and other C0/C1 controls;
// the report quotes that text, so it must never reach the stream as terminal
// control. The JSON answer keeps the raw bytes.
func SafeText(text string) string {
	if text == "" {
		return text
	}
	var out strings.Builder
	out.Grow(len(text))
	for index := 0; index < len(text); {
		if text[index] == 0x1b {
			index = escapeEnd(text, index)
			continue
		}
		r, size := utf8.DecodeRuneInString(text[index:])
		if r == utf8.RuneError && size == 1 {
			// An invalid byte is evidence the file held non-text; keep a
			// visible replacement rather than pass the byte to the terminal.
			out.WriteRune(utf8.RuneError)
			index++
			continue
		}
		index += size
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			out.WriteByte(' ')
		case r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f:
			// C0, DEL and C1 controls have no place in a report row.
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// escapeEnd consumes one ESC sequence from index, which names the ESC, and
// answers the index just past it. CSI runs to its final byte, OSC runs to
// BEL or ST, and any other escape is the two-byte form; a lone ESC at the
// end of the text consumes itself. It is the one scanner for width,
// stripping, styling and sanitizing, so the four cannot disagree about where
// a sequence ends.
func escapeEnd(text string, index int) int {
	if index+1 >= len(text) {
		return index + 1
	}
	switch text[index+1] {
	case '[':
		end := index + 2
		for end < len(text) && (text[end] < 0x40 || text[end] > 0x7e) {
			end++
		}
		if end < len(text) {
			end++
		}
		return end
	case ']':
		end := index + 2
		for end < len(text) {
			if text[end] == 0x07 {
				return end + 1
			}
			if text[end] == 0x1b && end+1 < len(text) && text[end+1] == '\\' {
				return end + 2
			}
			end++
		}
		return end
	default:
		return index + 2
	}
}

// DisplayWidth is a string's printed width: terminal escapes take no column.
func DisplayWidth(text string) int {
	width := 0
	for index := 0; index < len(text); {
		if text[index] == 0x1b {
			index = escapeEnd(text, index)
			continue
		}
		r, size := utf8.DecodeRuneInString(text[index:])
		index += size
		width += runeWidth(r)
	}
	return width
}

// runeWidth is the terminal cell count of one visible rune. The table covers
// the East Asian wide/fullwidth ranges and combining marks; it is the width
// the report and its tables align to.
func runeWidth(r rune) int {
	if r == 0 {
		return 0
	}
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r) {
		return 0
	}
	switch {
	case r >= 0x1100 && r <= 0x115f, // Hangul Jamo
		r >= 0x2e80 && r <= 0xa4cf && r != 0x303f, // CJK radicals .. Yi
		r >= 0xac00 && r <= 0xd7a3,                // Hangul syllables
		r >= 0xf900 && r <= 0xfaff,                // CJK compatibility ideographs
		r >= 0xfe10 && r <= 0xfe19,                // vertical forms
		r >= 0xfe30 && r <= 0xfe6f,                // CJK compatibility forms
		r >= 0xff00 && r <= 0xff60,                // fullwidth forms
		r >= 0xffe0 && r <= 0xffe6,
		r >= 0x1f300 && r <= 0x1f64f, // emoji
		r >= 0x1f900 && r <= 0x1f9ff,
		r >= 0x20000 && r <= 0x3fffd:
		return 2
	}
	return 1
}

// StripANSI drops terminal escape sequences: a line that has to wrap loses
// its paint rather than letting a wrap land inside an escape.
func StripANSI(text string) string {
	var out strings.Builder
	for index := 0; index < len(text); {
		if text[index] == 0x1b {
			index = escapeEnd(text, index)
			continue
		}
		out.WriteByte(text[index])
		index++
	}
	return out.String()
}

// Truncate shortens text to width printed columns, marking the cut with an
// ellipsis. ANSI sequences take no column and are kept out of the visible
// count, so a painted cell can be cut without splitting an escape.
func Truncate(text string, width int) string {
	if width <= 0 {
		return ""
	}
	if DisplayWidth(text) <= width {
		return text
	}
	runes := styledRunes(text)
	used := 0
	for cut, styled := range runes {
		next := used + runeWidth(styled.r)
		if next > width-1 {
			return renderStyled(runes[:cut]) + "…"
		}
		used = next
	}
	return text
}
