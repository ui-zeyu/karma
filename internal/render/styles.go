// Presentation palette for the report's own chrome: the heading bands, the
// rails, the legend, and the hit spans that land on target text. The colors
// themselves come from the form package, which states them once for every
// renderer; the line lexers that color a body by syntax live in internal/syntax
// and paint through the same palette. Every hit span and the legend share the
// same severity colors; syntax coloring stays low-saturation to keep clear of
// the red/yellow/cyan/green severity semantics.

package render

import (
	"io"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"karma/internal/form"
	"karma/internal/model"
)

// StreamColored reports whether the report's writer takes color: the stream's
// own environment answer (NO_COLOR off, CLICOLOR_FORCE on), the same detection
// the command-line skeleton's styles bind to. The chrome — bands, rails, the
// legend — colors through the renderer's own profile, which reads the same
// environment, so a report is colored or plain as a whole: a forced-color pipe
// colors its tables too, and a muted terminal mutes its bands too.
func StreamColored(w io.Writer) bool {
	return termenv.NewOutput(w).EnvColorProfile() != termenv.Ascii
}

// style is the palette's paint (form.Paint) under this package's shorter name:
// the panel's spans and the band styles are stated in it.
type style = form.Paint

// paintSpan is one stretch of a line to paint: the panel's hit spans and the
// syntax lexers' spans are the same type, so form.PaintLine paints both.
type paintSpan = form.Span

// lineStyler is one line's syntax spans, as internal/syntax states them: a
// lexer that carries state across lines (table column anchors) gets one
// instance per section.
type lineStyler = func(line string) []form.Span

var (
	// MutedColor is the palette's grey, stated with the rest of the colors in
	// the form package: the muted style, the grey rail of a quiet check and of
	// a skipped block, and the right-hand annotations share the same grey (a
	// darker grey is invisible in the user's light theme).
	MutedColor = form.MutedColor

	// The quiet marks, in this package's own style: form states them once, and
	// the report's chrome and its tests build their styles from the same values.
	// A severity color goes through severityStyle.
	mutedStyle  = form.MutedPaint()  // grey50
	accentStyle = form.AccentPaint() // bright_cyan
	dimStyle    = form.DimPaint()

	// listIDColor: the catalog's id column (karma list), plain blue so the
	// listing's selector vocabulary stands out from the titles without taking
	// one of the severity colors.
	listIDColor = lipgloss.Color("4")

	// Heading bands: a neutral dark background with white text, keeping clear
	// of the severity colors. Level one (the report's masthead and aspect
	// banners, and the listing's platform bands) is bold white on dark grey;
	// level two (the listing's aspect band and the report's check-title band)
	// steps down to a lighter grey with regular light-grey text, so the heading
	// tree's two levels read apart at a glance.
	bannerColor      = lipgloss.Color("236")
	bannerTextColor  = lipgloss.Color("15")
	subBandColor     = lipgloss.Color("238")
	subBandTextColor = lipgloss.Color("250")
	// bandMetaColor is the metadata a heading band carries on its right edge: the
	// masthead's author and the run's clock, and the notes on a check title. A
	// step dimmer than the band's own text and legible on both band greys; a
	// dimmer one beside the bold title read as a rendering fault.
	bandMetaColor = lipgloss.Color("246")
)

// bandStyle is the level-one heading band: the report's masthead and its aspect
// banners, and the listing's platform bands. subBandStyle is the level-two band
// behind the listing's aspect headings and the report's check titles — the same
// two steps in both views. subBandFill paints a panel head's padding with the
// band's own grey alone, so the strip reads solid from the rail to the right
// edge; a level-one strip's padding comes from the band's own style. The
// masthead's author and clock wear bandMetaColor on their band: a dimmer grey
// next to a label read as a rendering fault.
var (
	bandStyle = lipgloss.NewStyle().Bold(true).
			Background(bannerColor).Foreground(bannerTextColor)
	subBandStyle = lipgloss.NewStyle().
			Background(subBandColor).Foreground(subBandTextColor)
	subBandFill = lipgloss.NewStyle().Background(subBandColor)
)

// severityStyle is shared by hit spans and the legend; it covers the four
// signal severities only.
func severityStyle(severity model.Severity) style { return form.SeverityPaint(severity) }

// severityBorder is the rail hue. A critical hit span is white on red, so the
// border takes the red itself.
func severityBorder(severity model.Severity) lipgloss.Color { return form.SeverityBorder(severity) }

// ErrorColor and HintColor are the hues the command-line skeleton (help and
// error text) shares with the report: the signal hue of a high hit for a
// failure line, and of a medium hit for the suggestion that follows it, so a
// failure and its guidance read in the palette the evidence does.
var (
	ErrorColor = form.SeverityBorder(model.High)
	HintColor  = form.SeverityBorder(model.Medium)
)
