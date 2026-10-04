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
	// of the severity colors. Level one (the report's aspect banner and the
	// listing's platform band) is bold white on dark grey; level two (the
	// listing's aspect band and the report's check-title band) steps down to a
	// lighter grey with regular light-grey text, so the heading tree's two
	// levels read apart at a glance.
	bannerColor      = lipgloss.Color("236")
	bannerTextColor  = lipgloss.Color("15")
	subBandColor     = lipgloss.Color("238")
	subBandTextColor = lipgloss.Color("250")
	// subBandMetaColor is the metadata on the report's check-title band: a
	// step dimmer than the label, still legible on the band's grey.
	subBandMetaColor = lipgloss.Color("246")
)

// bandStyle is the level-one heading band: the report's aspect banners and the
// listing's platform bands. subBandStyle is the level-two band behind the
// listing's aspect headings and the report's check titles — the same two
// steps in both views. subBandFill paints the check-title band's padding (the
// band's grey alone), so the strip reads solid from the rail to the right edge.
var (
	bandStyle = lipgloss.NewStyle().Bold(true).
			Background(bannerColor).Foreground(bannerTextColor)
	subBandStyle = lipgloss.NewStyle().
			Background(subBandColor).Foreground(subBandTextColor)
	subBandFill = lipgloss.NewStyle().Background(subBandColor)
)

// severityTheme is the single source of the severity color language: the hit
// span and the rail hue of each signal level, indexed by Severity
// (Critical..Low). The quiet levels have neither.
var severityTheme = [...]struct {
	span   style
	border lipgloss.Color
}{
	{criticalStyle, "1"},
	{highStyle, "9"},
	{mediumStyle, "11"},
	{lowStyle, "14"},
}

// severityStyle is shared by hit spans and the legend; it covers the four
// signal severities only — benign and no-hit are both quiet lines.
func severityStyle(severity model.Severity) style {
	if severity < 0 || int(severity) >= len(severityTheme) {
		return style{}
	}
	return severityTheme[severity].span
}

// severityBorder is the border hue. A critical hit span is white on red, so the
// border takes the red itself.
func severityBorder(severity model.Severity) lipgloss.Color {
	if severity < 0 || int(severity) >= len(severityTheme) {
		return ""
	}
	return severityTheme[severity].border
}

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
func newLineStyler(syntax string) LineStyler {
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
func buildLineStyler(syntax string) LineStyler {
	switch syntax {
	case "ls-l":
		return styleLsL
	case "env":
		return styleEnv
	case "dmesg":
		return styleDmesg
	case "sshd-config":
		return styleSshdConfig
	case "ssh-pubkey":
		return styleSSHPublicKey
	case "colon":
		return styleColonTable
	case "lsmod":
		return styleLsmod
	case "ip-addr":
		return styleIPAddr
	case "table":
		return newTableStyler(nil, true).style
	case "top":
		// Cycle off: top -b's summary lines (banner, Tasks, %Cpu, MiB Mem) are
		// prose, not columns. The process table anchors on its all-caps header;
		// everything before it stays plain.
		return newTableStyler(nil, false).style
	case "df":
		return newTableStyler([]*regexp.Regexp{dfHeader}, true).style
	case "units":
		return newUnitStyler().style
	case "listen":
		return newTableStyler([]*regexp.Regexp{compile(`^Netid\s+State\s`), compile(`^Proto\s+Recv-Q\s+Send-Q\s`)}, true).style
	case "netstat":
		return newTableStyler([]*regexp.Regexp{compile(`^\s*Proto\s+Local`)}, true).style
	case "ip-keyval":
		return newKeyvalStyler().style
	case "fstab":
		return styleFstab
	case "reg":
		return styleReg
	case "pipe":
		return stylePipeTable
	case "powershell":
		return chromaLineStyler(chromaLexers["powershell"])
	case "bash":
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
