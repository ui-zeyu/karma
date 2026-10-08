// Package syntax colors one line of a body at a time: a lexer turns a line into
// the stretches that take a color, and whoever draws the line paints them
// through form. The colors themselves are the palette's, stated once in form;
// this package states which stretch of which shape takes which one.
//
// Each lexer lives in its own file (ls.go, table.go, reg.go, …), and bash and
// powershell go through chroma. Syntax colors stay low-saturation to keep clear
// of the severity colors the rules own: a hit has to read as a hit inside a
// colored cell.
package syntax

import (
	"regexp"

	"karma/internal/fault"
	"karma/internal/form"
	"karma/internal/model"
)

// --- regex helpers ---

func compile(expr string) *regexp.Regexp { return regexp.MustCompile(expr) }

// lineMatch is one line matched against a lexer's regexp. A lexer runs once per
// body row, so a named group is read back by name against the regexp's own name
// slice rather than through a map built for every row.
type lineMatch struct {
	re    *regexp.Regexp
	index []int
}

// matchLine matches one line against a lexer's regexp; ok is false when the
// regexp does not match it.
func matchLine(re *regexp.Regexp, line string) (lineMatch, bool) {
	index := re.FindStringSubmatchIndex(line)
	return lineMatch{re: re, index: index}, index != nil
}

// span returns the byte span of one named group; ok is false when the group did
// not take part in the match, which paints nothing either way.
func (m lineMatch) span(name string) (start, end int, ok bool) {
	group := m.re.SubexpIndex(name)
	if group < 0 || m.index[2*group] < 0 {
		return 0, 0, false
	}
	return m.index[2*group], m.index[2*group+1], true
}

// style is the palette's paint (form.Paint) under this package's shorter name:
// the lexers here are tables of color rules, and a span's own field reads best
// beside them.
type style = form.Paint

// paintSpan is one stretch of a line to paint, under the name the lexers read
// it by. It is form's own span type and not a second one: the colors, the
// sequences around a run and the way a run is painted are the palette's.
type paintSpan = form.Span

var (
	mutedStyle   = form.MutedPaint() // grey50
	dimStyle     = form.DimPaint()
	commentColor = style{Faint: true}
	keywordColor = style{FG: "5"} // magenta
	stringColor  = style{FG: "4"} // blue, same as Number
)

// lineStyler produces syntax spans for one body line; a lexer that carries state
// across lines (table column anchors) gets one instance per check, built by
// Painter.
type lineStyler func(line string) []form.Span

// Painter returns the line painter for one declared syntax, with insurance: a
// lexer panic (odd target output hitting a hard-coded line shape) permanently
// degrades this painter to plain text, while hit highlighting and body output
// carry on. A syntax with no lexer — or the empty one — returns nil, and the
// caller prints the line as it is.
func Painter(syntax model.Syntax) func(line string) []form.Span {
	return safeLineStyler(buildLineStyler(syntax))
}

// safeLineStyler wraps a lexer with insurance: an instance that blew up once is
// permanently degraded to plain text (its cross-line state may already be
// polluted, and coloring against a wrong anchor is worse than plain text). The
// boundary is the fault package's, like every other one a run crosses.
func safeLineStyler(styler lineStyler) lineStyler {
	if styler == nil {
		return nil
	}
	poisoned := false
	return func(line string) []form.Span {
		if poisoned {
			return nil
		}
		spans, err := fault.Result("line styler", func() []form.Span { return styler(line) })
		if err != nil {
			poisoned = true
			return nil
		}
		return spans
	}
}

// syntaxStylers is the syntax table: one constructor per declared syntax, so a
// syntax and its coloring are one entry instead of one branch of a switch. A
// syntax with no entry declares no coloring.
var syntaxStylers = map[model.Syntax]func() lineStyler{
	model.SyntaxLsL:        func() lineStyler { return styleLsL },
	model.SyntaxEnv:        func() lineStyler { return styleEnv },
	model.SyntaxDmesg:      func() lineStyler { return styleDmesg },
	model.SyntaxSshdConfig: func() lineStyler { return styleSshdConfig },
	model.SyntaxSSHPubkey:  func() lineStyler { return styleSSHPublicKey },
	model.SyntaxColon:      func() lineStyler { return styleColonTable },
	model.SyntaxLsmod:      func() lineStyler { return styleLsmod },
	model.SyntaxIPAddr:     func() lineStyler { return styleIPAddr },
	model.SyntaxTable:      func() lineStyler { return newTableStyler(nil, true).style },
	model.SyntaxTree:       func() lineStyler { return styleTree },
	// Cycle off: top -b's summary lines (banner, Tasks, %Cpu, MiB Mem) are
	// prose, not columns. The process table anchors on its all-caps header;
	// everything before it stays plain.
	model.SyntaxTop:       func() lineStyler { return newTableStyler(nil, false).style },
	model.SyntaxLastlog:   func() lineStyler { return newTableStyler([]*regexp.Regexp{lastlogHeader}, true).style },
	model.SyntaxUnits:     func() lineStyler { return newUnitStyler().style },
	model.SyntaxUnitFiles: func() lineStyler { return styleUnitFiles },
	model.SyntaxTimers:    func() lineStyler { return timersRow },
	model.SyntaxListen: func() lineStyler {
		return newTableStyler([]*regexp.Regexp{compile(`^Netid\s+State\s`), compile(`^Proto\s+Recv-Q\s+Send-Q\s`)}, true).style
	},
	model.SyntaxNetstat: func() lineStyler { return newTableStyler([]*regexp.Regexp{compile(`^\s*Proto\s+Local`)}, true).style },
	model.SyntaxPkgHistory: func() lineStyler {
		return stylePkgHistory
	},
	model.SyntaxReg:  func() lineStyler { return styleReg },
	model.SyntaxPipe: func() lineStyler { return stylePipeTable },
	model.SyntaxPowerShell: func() lineStyler {
		return chromaLineStyler(chromaLexers["powershell"])
	},
	model.SyntaxBash: func() lineStyler { return chromaLineStyler(chromaLexers["bash"]) },
}

// buildLineStyler resolves one declared syntax through the table; an unknown
// declaration means no highlighting.
func buildLineStyler(syntax model.Syntax) lineStyler {
	if build, ok := syntaxStylers[syntax]; ok {
		return build()
	}
	return nil
}
