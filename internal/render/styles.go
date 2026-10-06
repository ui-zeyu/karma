// Presentation palette and inline coloring: the severity color language, the
// legend source, the span machinery, and the syntax dispatch table.
//
// render only does layout (boxes, progress, budget); coloring of text coming
// from the target all comes from here. Every hit span and the legend share the
// same severity colors; syntax coloring stays low-saturation to keep clear of
// the red/yellow/cyan/green severity semantics. Each highlighting rule lives in
// its own file (ls.go, table.go, reg.go, …); bash and powershell go through
// chroma, line-shaped output uses the built-in pseudo-lexers.

package render

import (
	"regexp"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"karma/internal/model"
)

// --- regex helpers ---

func compile(expr string) *regexp.Regexp { return regexp.MustCompile(expr) }

// findSubindex returns the byte spans of the named groups; a group that did not
// match is skipped.
func findSubindex(re *regexp.Regexp, line string) map[string][2]int {
	idx := re.FindStringSubmatchIndex(line)
	if idx == nil {
		return nil
	}
	out := map[string][2]int{}
	for i, name := range re.SubexpNames() {
		if name == "" || idx[2*i] < 0 {
			continue
		}
		out[name] = [2]int{idx[2*i], idx[2*i+1]}
	}
	return out
}

// style is the smallest description of one painting; it turns into lipgloss
// SGR output.
type style struct {
	fg     lipgloss.Color
	bg     lipgloss.Color
	bold   bool
	faint  bool
	italic bool
}

func (s style) seq() lipgloss.Style {
	out := lipgloss.NewStyle()
	if s.bold {
		out = out.Bold(true)
	}
	if s.faint {
		out = out.Faint(true)
	}
	if s.italic {
		out = out.Italic(true)
	}
	if s.fg != "" {
		out = out.Foreground(s.fg)
	}
	if s.bg != "" {
		out = out.Background(s.bg)
	}
	return out
}

var (
	// MutedColor is the single source of muting: the muted style, the grey rail
	// of a quiet check and of a skipped block, and the right-hand annotations
	// share the same grey (a darker grey is invisible in the user's light
	// theme).
	MutedColor    = lipgloss.Color("244")
	criticalStyle = style{fg: "15", bg: "1", bold: true} // bold white on red
	highStyle     = style{fg: "9", bold: true}           // bold bright_red
	mediumStyle   = style{fg: "11", bold: true}          // bold bright_yellow
	lowStyle      = style{fg: "14"}                      // bright_cyan
	mutedStyle    = style{fg: MutedColor}                // grey50
	accentStyle   = style{fg: "14"}                      // bright_cyan
	dimStyle      = style{faint: true}

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

// severityHue is one signal level's color language: the hit span and the rail
// hue.
type severityHue struct {
	span   style
	border lipgloss.Color
}

// severityTheme is the single source of the severity color language, indexed by
// Severity (Critical..Low). The quiet levels have no entry: benign and no-hit
// are both quiet lines.
var severityTheme = [...]severityHue{
	{criticalStyle, "1"},
	{highStyle, "9"},
	{mediumStyle, "11"},
	{lowStyle, "14"},
}

// severityHueOf is the one lookup every severity color goes through; a quiet
// level has no hue, so its paint is the zero value.
func severityHueOf(severity model.Severity) severityHue {
	if severity < 0 || int(severity) >= len(severityTheme) {
		return severityHue{}
	}
	return severityTheme[severity]
}

// severityStyle is shared by hit spans and the legend; it covers the four
// signal severities only.
func severityStyle(severity model.Severity) style { return severityHueOf(severity).span }

// severityBorder is the rail hue. A critical hit span is white on red, so the
// border takes the red itself.
func severityBorder(severity model.Severity) lipgloss.Color { return severityHueOf(severity).border }

// ErrorColor and HintColor are the hues the command-line skeleton (help and
// error text) shares with the report: the signal hue of a high hit for a
// failure line, and of a medium hit for the suggestion that follows it, so a
// failure and its guidance read in the palette the evidence does.
var (
	ErrorColor = severityTheme[model.High].border
	HintColor  = severityTheme[model.Medium].border
)

// Syntax coloring uses low-saturation dark colors and is applied before hit
// spans (syntax < hits); bright magenta reads like the severity red in a light
// terminal, so keywords use dark magenta.
var (
	commentColor = style{faint: true}
	keywordColor = style{fg: "5"} // magenta
	stringColor  = style{fg: "4"} // blue, same as Number
)

// Span is one painted span (byte offsets).
type Span struct {
	Start int
	End   int
	Style style
}

// LineStyler produces syntax spans for one body line; a lexer that carries
// state across lines (table column anchors) gets one instance per check, built
// by newLineStyler.
type LineStyler func(line string) []Span

// newLineStyler returns the inline coloring function for the declared syntax,
// with insurance: a lexer panic (odd target output hitting a hard-coded line
// shape) permanently degrades this check's syntax coloring to plain text,
// while hit highlighting and body output carry on.
func newLineStyler(syntax model.Syntax) LineStyler {
	return safeLineStyler(buildLineStyler(syntax))
}

// safeLineStyler wraps a lexer with insurance: an instance that blew up once is
// permanently degraded to plain text (its cross-line state may already be
// polluted, and coloring against a wrong anchor is worse than plain text).
func safeLineStyler(styler LineStyler) LineStyler {
	if styler == nil {
		return nil
	}
	poisoned := false
	return func(line string) (spans []Span) {
		if poisoned {
			return nil
		}
		defer func() {
			if recover() != nil {
				poisoned, spans = true, nil
			}
		}()
		return styler(line)
	}
}

// buildLineStyler is the syntax table. Built-in pseudo-lexers are reused
// directly; bash goes through chroma; an unknown declaration means no
// highlighting.
func buildLineStyler(syntax model.Syntax) LineStyler {
	switch syntax {
	case model.SyntaxLsL:
		return styleLsL
	case model.SyntaxEnv:
		return styleEnv
	case model.SyntaxDmesg:
		return styleDmesg
	case model.SyntaxSshdConfig:
		return styleSshdConfig
	case model.SyntaxSSHPubkey:
		return styleSSHPublicKey
	case model.SyntaxColon:
		return styleColonTable
	case model.SyntaxLsmod:
		return styleLsmod
	case model.SyntaxIPAddr:
		return styleIPAddr
	case model.SyntaxTable:
		return newTableStyler(nil, true).style
	case model.SyntaxTop:
		// Cycle off: top -b's summary lines (banner, Tasks, %Cpu, MiB Mem) are
		// prose, not columns. The process table anchors on its all-caps header;
		// everything before it stays plain.
		return newTableStyler(nil, false).style
	case model.SyntaxDf:
		return newTableStyler([]*regexp.Regexp{dfHeader}, true).style
	case model.SyntaxLastlog:
		return newTableStyler([]*regexp.Regexp{lastlogHeader}, true).style
	case model.SyntaxUnits:
		return newUnitStyler().style
	case model.SyntaxListen:
		return newTableStyler([]*regexp.Regexp{compile(`^Netid\s+State\s`), compile(`^Proto\s+Recv-Q\s+Send-Q\s`)}, true).style
	case model.SyntaxNetstat:
		return newTableStyler([]*regexp.Regexp{compile(`^\s*Proto\s+Local`)}, true).style
	case model.SyntaxIPKeyval:
		return newKeyvalStyler().style
	case model.SyntaxPkgHistory:
		return stylePkgHistory
	case model.SyntaxFstab:
		return styleFstab
	case model.SyntaxReg:
		return styleReg
	case model.SyntaxPipe:
		return stylePipeTable
	case model.SyntaxPowerShell:
		return chromaLineStyler(chromaLexers["powershell"])
	case model.SyntaxBash:
		return chromaLineStyler(chromaLexers["bash"])
	}
	return nil
}

// paintLine paints one line by span: spans apply in stacking order, later ones
// covering earlier ones (the syntax layer lands first, hit spans and comment
// muting later). Non-overlapping spans leave the output unchanged, and an empty
// span set returns the text as is.
//
// The line is cut at every span boundary; each cut segment takes the last span
// covering it whole, and neighbouring segments with the same winner merge back
// into one run. Every maximal run of bytes painted by the same span is bounded
// by span boundaries, so the result matches the per-byte rule without touching
// each byte.
func paintLine(text string, spans []Span) string {
	if len(spans) == 0 {
		return text
	}
	cuts := []int{0, len(text)}
	for _, span := range spans {
		start, end := max(span.Start, 0), min(span.End, len(text))
		if end > start { // a malformed span paints nothing, as before
			cuts = append(cuts, start, end)
		}
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	var out strings.Builder
	runStart, winner := 0, -1
	for index := 1; index < len(cuts); index++ {
		start, end := cuts[index-1], cuts[index]
		next := -1
		for probe, span := range spans { // later spans paint over earlier ones
			if span.Start <= start && end <= span.End {
				next = probe
			}
		}
		if next == winner {
			continue
		}
		if winner >= 0 {
			out.WriteString(spans[winner].Style.seq().Render(text[runStart:start]))
		} else {
			out.WriteString(text[runStart:start])
		}
		winner, runStart = next, start
	}
	if winner >= 0 {
		return out.String() + spans[winner].Style.seq().Render(text[runStart:])
	}
	return out.String() + text[runStart:]
}
