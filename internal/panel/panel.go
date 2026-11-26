// Package panel is the hand-drawn chrome the report and the command-line help
// screens share: the two heading bands, the rail panel, and the text
// primitives the rail wraps with. The palette and the rail's shape live here
// once; audit's report and cli's help are the two compositions.
package panel

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

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
	if utf8.RuneCountInString(left)+utf8.RuneCountInString(right) > width {
		right = ""
		left = Truncate(left, width)
	}
	fill := width - utf8.RuneCountInString(left) - utf8.RuneCountInString(right)
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
// band, and body rows indented two columns.
func Rail(head string, body []string, width, railColor int, color bool) string {
	inner := width - 2
	lines := []string{head}
	for _, line := range body {
		line = strings.TrimRight(line, " ")
		for _, wrapped := range Wrap(line, inner-2) {
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
		if text[index] == 0x1b && index+1 < len(text) && text[index+1] == '[' {
			end := index + 2
			for end < len(text) && (text[end] < 0x40 || text[end] > 0x7e) {
				end++
			}
			if end < len(text) {
				end++
			}
			sequence := text[index:end]
			if sequence[len(sequence)-1] == 'm' {
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

// DisplayWidth is a string's printed width: ANSI escapes take no column.
func DisplayWidth(text string) int {
	width := 0
	for index := 0; index < len(text); {
		if text[index] == 0x1b {
			for index < len(text) && text[index] != 'm' {
				index++
			}
			index++
			continue
		}
		_, size := utf8.DecodeRuneInString(text[index:])
		index += size
		width++
	}
	return width
}

// StripANSI drops SGR sequences: a line that has to wrap loses its paint
// rather than letting a wrap land inside an escape.
func StripANSI(text string) string {
	var out strings.Builder
	for index := 0; index < len(text); {
		if text[index] == 0x1b {
			for index < len(text) && text[index] != 'm' {
				index++
			}
			index++
			continue
		}
		out.WriteByte(text[index])
		index++
	}
	return out.String()
}

// Truncate shortens text to width runes, marking the cut with an ellipsis.
func Truncate(text string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= width {
		return text
	}
	if width == 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}
