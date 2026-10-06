// Package render is the presentation layer: the report header, check panels
// released in catalog order, and aspect banners.
//
// Presentation only reads the Document, the outcome, and the structured skip
// reasons; the budget, source titles, and right-hand annotations are decisions
// of this layer and are never written back to the document. A finished check
// is taken into a table first, and only written back once the catalog prefix
// is complete, so the on-screen order is always the aspect order. Layout is
// entirely drawn by lipgloss: an aspect is a full-width banner and a check
// title is a second-level band — the same two heading steps as the listing —
// while the panel is a left rail (a thick rail in the severity color for
// signals, a grey rail otherwise) with the body indented two more columns, and
// over-long lines are soft-wrapped by lipgloss — continuation lines share the
// body indent and the rail never breaks. All target text is shown as it is;
// hits come from painted spans and a trailing reason, with the palette in
// styles.
//
// This file holds the geometry, the heading bands and the rail block. The
// report's two surfaces are built beside it: masthead.go draws the header and
// its fact grid, panel.go one check's panel and its display budget, and live.go
// the observer that releases the panels in catalog order.
package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	xansi "github.com/charmbracelet/x/ansi"
	"github.com/samber/lo"

	"karma/internal/model"
)

// Layout constants inside a rail panel: one column of padding on each side,
// and the body one column deeper than the head. The right edge keeps one
// column of slack so no line reaches the terminal's last column.
const (
	headPad  = 1
	bodyPad  = 2
	rightPad = 1
)

// mastheadBand is the report's level-one band: KARMA on the left and the author
// on the right edge of the same strip.
func mastheadBand(term int) string { return titleBand("KARMA", authorLabel, term) }

// titleBand is a level-one band: the label on the left, the meta on its right
// edge, filled out to the line.
func titleBand(label, meta string, term int) string {
	rows := bandHead(bandStyle, label, meta,
		style{fg: bandMetaColor, bg: bannerColor}, lineWidth(term))
	return trimPadding(strings.Join(rows, "\n"))
}

// headingBand is a level-one heading band: a full-width strip with bold white
// uppercase text. It is the report's aspect banner and the catalog listing's
// platform band, so both views say a level-one heading the same way. The band's
// fill is trimmed off again when it carries no color: a plain report has no use
// for the padding.
func headingBand(name string, term int) string {
	return trimPadding(fillBand(" "+strings.ToUpper(name), lineWidth(term), bandStyle))
}

// fillBand fills the line with a band: the label is truncated when it does not
// fit, and the pad spaces are handed to lipgloss so they carry the band's
// background (the spaces Width pads with would not).
func fillBand(label string, width int, st lipgloss.Style) string {
	if lipgloss.Width(label) > width {
		label = xansi.Truncate(label, width, "…")
	}
	return st.Render(label + strings.Repeat(" ", width-lipgloss.Width(label)))
}

// SyntaxLine paints one line's declared syntax — the report's body-line
// coloring without hit spans — so a caller outside the report (the built-in
// readers) prints the same paint its panels get. An unknown syntax returns
// the line unchanged. The styler is built here, so this is the shape for a
// line-shaped lexer; a table lexer, which carries its column anchors from line
// to line, needs one styler over the whole output.
func SyntaxLine(syntax model.Syntax, line string) string {
	styler := newLineStyler(syntax)
	if styler == nil {
		return line
	}
	return paintLine(line, styler(line))
}

// Masthead and Panel expose the report's own surfaces to callers outside it:
// the command-line skeleton's help screen and its usage blocks reuse them, so
// the tool's first screen and its report read as one language.
// Masthead draws the report's first panel: the level-one band with the byline
// on its right edge, the level-two head carrying the build's version, and the
// body lines inside the same rail. The command-line skeleton's help screen
// wears it, with the command path as its band label and the command's own
// description as its body.
func Masthead(label, version string, body []string, term int) string {
	band := titleBand(strings.ToUpper(label), authorLabel, term)
	head := []string{fillBand(" "+version, railInner(term), subBandStyle)}
	return band + "\n" + checkBlock(model.Info, head, body, term)
}

// Panel renders label as a quiet rail panel head over the body rows.
func Panel(label string, rows []string, term int) string {
	head := []string{fillBand(" "+strings.ToUpper(label), railInner(term), subBandStyle)}
	return checkBlock(model.Info, head, rows, term)
}

// lineWidth is the widest a line may be: the terminal width minus one column of
// right-edge slack.
func lineWidth(term int) int { return max(term-1, 8) }

// railInner is the usable width to the right of the rail (padding included).
func railInner(term int) int { return max(lineWidth(term)-1, 8) }

// headTextWidth is the text width available on a heading band's first line:
// the band gives up one pair of padding.
func headTextWidth(band int) int { return max(band-headPad-rightPad, 4) }

// textWidth is the text width available for the panel body: the body is
// indented two more columns and then gives up one pair of padding.
func textWidth(term int) int { return max(railInner(term)-bodyPad-rightPad, 4) }

// checkBlock is a check panel's rail: a half-block rail, carrying the severity
// color for signals and muted otherwise. lipgloss draws the rail; inside it
// the head rows form the check title band (level two of the heading tree,
// filled to the inner width by bandHead) and the body is indented two more
// columns; over-long lines are soft-wrapped by lipgloss's Width, with
// continuation lines sharing the body indent and the rail unbroken. Rows are
// bounded first (see boundRow), so nothing reaches the terminal's last column.
//
// The rail pads every line out to the block width, so the finished panel goes
// through trimPadding before it is returned.
func checkBlock(severity model.Severity, head []string, body []string, term int) string {
	st := lipgloss.NewStyle().BorderLeft(true).
		BorderStyle(lipgloss.OuterHalfBlockBorder())
	if severity.IsSignal() {
		st = st.BorderForeground(severityBorder(severity))
	} else {
		st = st.BorderForeground(MutedColor)
	}
	inner := railInner(term)
	text := strings.Join(head, "\n")
	if len(body) > 0 {
		rows := lo.Map(body, func(row string, _ int) string { return boundRow(row, textWidth(term)) })
		box := lipgloss.NewStyle().Padding(0, rightPad, 0, bodyPad).Width(inner)
		text += "\n" + box.Render(strings.Join(rows, "\n"))
	}
	return trimPadding(st.Render(text))
}

// trimPadding drops the plain spaces lipgloss pads a rendered block out to its
// width with. The padding places the rail and gives a wrapped line its room;
// none of it is visible, and a redirected report would otherwise be half
// spaces. A band row's padding is the band's own fill, painted inside its style
// and closed by that style's reset, so it is not plain trailing space and stays.
func trimPadding(block string) string {
	lines := strings.Split(block, "\n")
	for index, line := range lines {
		lines[index] = strings.TrimRight(line, " ")
	}
	return strings.Join(lines, "\n")
}

// boundRow keeps a row inside the given width before lipgloss wraps it. A row
// that already fits is returned untouched (the common case, so the established
// layout is unchanged). Otherwise it is broken between words and after slashes,
// and a token that survives that — a base64 argument, a path with no
// separators — is broken by character: lipgloss's own wrap cannot split such a
// token, and one of them would widen the whole panel past the terminal's last
// column.
func boundRow(row string, width int) string {
	// Display width never exceeds the byte count, so a row whose bytes fit
	// cannot be too wide: the row that fits — nearly every one — skips the
	// grapheme-by-grapheme measurement.
	if len(row) <= width || lipgloss.Width(row) <= width {
		return row
	}
	wrapped := xansi.Wordwrap(row, width, "/")
	if lipgloss.Width(wrapped) <= width {
		return wrapped
	}
	return xansi.Hardwrap(wrapped, width, false)
}

// bandHead lays a panel head on a heading band: the label on the left,
// metadata on the right, every cell painted onto the band so the strip reads
// solid from the rail to the right edge (a Width pad would stay unpainted —
// see fillBand). fill paints the band's padding and says which heading level
// the band is, and band is how wide that strip is: the rail's inner width for a
// panel head, the line width for the masthead's own level-one band. Metadata
// that does not fit beside the label drops to its own band row, aligned with the
// label.
func bandHead(fill lipgloss.Style, label, meta string, metaStyle style, band int) []string {
	text := headTextWidth(band)
	labelCell := fill.Render(strings.Repeat(" ", headPad) + label)
	if meta == "" {
		return []string{filledRow(fill, labelCell, band)}
	}
	if lipgloss.Width(label)+2+lipgloss.Width(meta) <= text {
		gap := text - lipgloss.Width(label) - lipgloss.Width(meta)
		row := labelCell + fill.Render(strings.Repeat(" ", gap)) +
			metaStyle.seq().Render(meta)
		return []string{filledRow(fill, row, band)}
	}
	rows := []string{filledRow(fill, labelCell, band)}
	for _, line := range strings.Split(boundRow(meta, text), "\n") {
		rows = append(rows, filledRow(fill,
			fill.Render(strings.Repeat(" ", headPad))+metaStyle.seq().Render(line), band))
	}
	return rows
}

// filledRow pads a band row out to the band's width with painted spaces, so the
// band runs edge to edge.
func filledRow(fill lipgloss.Style, row string, band int) string {
	pad := band - lipgloss.Width(row)
	if pad > 0 {
		row += fill.Render(strings.Repeat(" ", pad))
	}
	return row
}
