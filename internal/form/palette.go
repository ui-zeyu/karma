// The palette: the colors a form paints with, and the ones the report's own
// chrome shares. It is stated once, as raw colors, so the line-span machinery
// the remaining lexers use builds its own styles from the same values.

package form

import (
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"karma/internal/model"
)

// Paint is one style's raw colors: the form the palette is stated in, so every
// renderer builds its own style values from one source.
type Paint struct {
	FG     string
	BG     string
	Bold   bool
	Faint  bool
	Italic bool
}

// Style is Paint as a lipgloss style.
func (p Paint) Style() lipgloss.Style {
	out := lipgloss.NewStyle()
	if p.Bold {
		out = out.Bold(true)
	}
	if p.Faint {
		out = out.Faint(true)
	}
	if p.Italic {
		out = out.Italic(true)
	}
	if p.FG != "" {
		out = out.Foreground(lipgloss.Color(p.FG))
	}
	if p.BG != "" {
		out = out.Background(lipgloss.Color(p.BG))
	}
	return out
}

// Render paints one run of one line. It is Style().Render for a run that is
// already a single line, and both callers paint a row a run at a time: a
// table cell and a permission bit are each their own run, so a listing line is
// a dozen of them. lipgloss rebuilds its property map and its sequence on
// every call, and the pair a style opens and closes with is that style's own,
// so it is derived once per style and kept. Text carrying a tab or a line
// break goes to lipgloss, whose own normalization those runs need.
func (p Paint) Render(text string) string {
	if strings.ContainsAny(text, "\t\r\n") {
		return p.Style().Render(text)
	}
	open, close := p.sequences()
	if open == "" {
		return text
	}
	return open + text + close
}

// sequenceKey is what one cached pair is keyed by: the style, and the color
// profile it was derived under, so a run forced onto another profile gets that
// profile's sequences.
type sequenceKey struct {
	profile termenv.Profile
	paint   Paint
}

// sequencePair is the cached pair.
type sequencePair struct{ open, close string }

// sequenceCache keeps one pair per style and profile. A report paints a row a
// run at a time, so the same few styles are asked for their sequences on every
// line, and the derivation is worth doing once.
var sequenceCache sync.Map

// sequences derives this style's open and close sequences. The pair is read off
// lipgloss itself, from a one-byte run: what it wraps that byte with is what it
// wraps every run of this style with.
func (p Paint) sequences() (open, close string) {
	key := sequenceKey{profile: lipgloss.ColorProfile(), paint: p}
	if cached, ok := sequenceCache.Load(key); ok {
		pair := cached.(sequencePair)
		return pair.open, pair.close
	}
	open, close = splitSequences(p.Style().Render("\x00"))
	sequenceCache.Store(key, sequencePair{open: open, close: close})
	return open, close
}

// splitSequences takes the wrapped byte apart: what precedes the mark opens a
// run and what follows it closes one. A profile that writes no escapes returns
// the byte alone, which is an empty pair.
func splitSequences(wrapped string) (open, close string) {
	at := strings.Index(wrapped, "\x00")
	return wrapped[:at], wrapped[at+1:]
}

// MutedColor is the single source of muting: the muted style, the grey rail of
// a quiet check and of a skipped block, and the right-hand annotations share
// the same grey (a darker grey is invisible in the user's light theme).
var MutedColor = lipgloss.Color("244")

// MutedPaint is the grey of incidental text.
func MutedPaint() Paint { return Paint{FG: string(MutedColor)} }

// DimPaint is the faint mark of a note the caller inserted.
func DimPaint() Paint { return Paint{Faint: true} }

// AccentPaint is the accent a section title or a spinner takes.
func AccentPaint() Paint { return Paint{FG: "14"} }

// Hue is one severity's color language: the paint of a hit, and the hue of the
// rail beside it. A critical hit is white on red, so its border takes the red
// itself.
type Hue struct {
	Paint  Paint
	Border lipgloss.Color
}

// severityHues is the single source of the severity color language, indexed by
// Severity (Critical..Low). The quiet levels have no entry: benign and no-hit
// are both quiet lines.
var severityHues = [...]Hue{
	{Paint{FG: "15", BG: "1", Bold: true}, "1"}, // bold white on red
	{Paint{FG: "9", Bold: true}, "9"},           // bold bright_red
	{Paint{FG: "11", Bold: true}, "11"},         // bold bright_yellow
	{Paint{FG: "14"}, "14"},                     // bright_cyan
}

// SeverityHue is the one lookup every severity color goes through; ok is false
// for a quiet level, which has no hue (its paint is the zero value).
func SeverityHue(severity model.Severity) (Hue, bool) {
	if severity < 0 || int(severity) >= len(severityHues) {
		return Hue{}, false
	}
	return severityHues[severity], true
}

// SeverityPaint is the paint of one hit; a quiet level paints nothing.
func SeverityPaint(severity model.Severity) Paint {
	hue, _ := SeverityHue(severity)
	return hue.Paint
}

// Severities returns every level with a hue, in severity order: the signal
// levels, critical first. It is what a legend walks.
func Severities() []model.Severity {
	levels := make([]model.Severity, len(severityHues))
	for index := range severityHues {
		levels[index] = model.Severity(index)
	}
	return levels
}

// SeverityBorder is the rail hue; a quiet level has none.
func SeverityBorder(severity model.Severity) lipgloss.Color {
	hue, _ := SeverityHue(severity)
	return hue.Border
}

// Tints is how many colors the structural cycle holds.
const Tints = 5

// tintPaints is the structural hue cycle: the blue family first, then the dark
// family. Five tints take a table's columns and a tree's nesting levels apart
// without taking a severity color, so a hit inside a cell or on a node still
// reads as a hit.
var tintPaints = [...]Paint{
	{FG: "4"}, {FG: "3"}, {FG: "5"}, {FG: "2"}, {FG: "6"},
}

// ColumnPaint is the tint of the index-th column of the cycle.
func ColumnPaint(index int) Paint { return tintPaints[index%Tints] }

// LevelPaint is the tint of a tree's level-th nesting under its root — the
// first branch is level 1, and a lead's bars carry the hue of the level each
// one descends from. The cycle repeats past its end, and level 0, a root's own
// line, carries no branch and stays muted.
func LevelPaint(level int) Paint {
	if level < 1 {
		return MutedPaint()
	}
	return tintPaints[(level-1)%Tints]
}
