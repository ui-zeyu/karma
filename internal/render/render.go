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
// over-long lines are soft-wrapped by lipgloss — continuation
// lines share the body indent and the rail never breaks. All target text is
// shown as it is; hits come from painted spans and a trailing reason, with the
// palette in styles.
package render

import (
	"cmp"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	xansi "github.com/charmbracelet/x/ansi"
	"github.com/samber/lo"

	"karma/internal/model"
	"karma/internal/textutil"
)

// Layout constants inside a rail panel: one column of padding on each side,
// and the body one column deeper than the head. The right edge keeps one
// column of slack so no line reaches the terminal's last column.
const (
	headPad  = 1
	bodyPad  = 2
	rightPad = 1
	// factGap and factColumnGap place the masthead's labeled facts: a value
	// starts a two-column gap after its label, and a second column starts a
	// four-column gap after the first. factMinValue is the narrowest value
	// column worth a second column.
	factGap       = 2
	factColumnGap = 4
	factMinValue  = 18
)

// Comment lines (the same shape as the former global comment filter): not
// filtered, painted muted
var commentLine = regexp.MustCompile(`^[ \t]*#`)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// HeaderInfo is what the masthead says beyond the host facts: how the run
// reached the target, when it started, and how much of the catalog it covers.
type HeaderInfo struct {
	Channel   string    // the channel and what it reaches: "local", "ssh root@host:22"
	Version   string    // the build's version
	Started   time.Time // when collection began
	Selected  int       // checks this run collects
	Total     int       // checks the platform's catalog holds
	Selectors []string  // the run's selector words, empty for the whole catalog
	SaveDir   string    // the --save directory, empty when evidence is not written
	Floor     model.SeverityFloor
}

// RenderHeader draws the report's masthead: the KARMA band — the same
// full-width level-one strip an aspect banner wears, covering the rail's own
// column, with the author on its right edge — over a rail panel whose head band
// is the level-two step every check title wears, carrying the build's version
// and the run's clock. Below it the facts line up as a table: which host,
// reached how, running what, collected by whom, and how much of the catalog
// this run covers.
func RenderHeader(w io.Writer, facts model.HostFacts, info HeaderInfo, width int) {
	head := bandHead(subBandFill, subBandStyle.Render(info.Version), clock(info.Started),
		style{fg: bandMetaColor, bg: subBandColor}, railInner(width))
	body := factGrid(mastheadFacts(facts, info), textWidth(width))
	fmt.Fprintln(w, mastheadBand(width))
	fmt.Fprintln(w, checkBlock(model.Info, head, body, width))
	fmt.Fprintln(w)
}

// authorLabel is the report's byline, written on the right edge of the
// masthead's level-one band the way every panel head carries its metadata.
const authorLabel = "yuyy"

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

// clock is the run's start time in the operator's own zone: a report is read
// next to the machine that produced it.
func clock(started time.Time) string {
	if started.IsZero() {
		return ""
	}
	return started.Format("2006-01-02 15:04:05 -0700")
}

// mastheadFacts is the masthead's fact block in reading order: the target on
// the left of every row, the run that collected it on the right.
func mastheadFacts(facts model.HostFacts, info HeaderInfo) []fact {
	rows := []fact{
		{label: "host", value: cmp.Or(facts.Hostname, "unknown"), styl: style{bold: true}},
		{label: "channel", value: info.Channel},
		{label: "distro", value: cmp.Or(facts.OsPretty, "unknown distro")},
		{label: "account", value: accountCell(facts)},
		{label: "kernel", value: cmp.Or(facts.Kernel, "unknown")},
		{label: "checks", value: scopeLine(info)},
	}
	if info.SaveDir != "" {
		rows = append(rows, fact{label: "evidence", value: info.SaveDir})
	}
	return append(rows, fact{label: "severity", chips: legendChips(info.Floor), full: true})
}

// accountCell is the collecting identity: the account name where the channel
// reports one (Windows), the uid otherwise, with root spelled out.
func accountCell(facts model.HostFacts) string {
	switch {
	case facts.User != "":
		return facts.User
	case facts.IsRoot():
		return "root (uid 0)"
	case facts.UID >= 0:
		return fmt.Sprintf("uid %d", facts.UID)
	}
	return ""
}

// scopeLine is how much of the catalog the run covers: the count alone when the
// whole catalog runs, and the words that narrowed it behind the count.
func scopeLine(info HeaderInfo) string {
	switch {
	case len(info.Selectors) > 0:
		return fmt.Sprintf("%d of %d (%s)", info.Selected, info.Total, strings.Join(info.Selectors, " "))
	case info.Total > info.Selected:
		return fmt.Sprintf("%d of %d", info.Selected, info.Total)
	}
	return strconv.Itoa(info.Selected)
}

// legendChips is the severity key, one item per signal level: its dot in its own
// color, muted where the run's floor excludes it — those levels cannot appear in
// this report — with the floor's own name after them.
func legendChips(floor model.SeverityFloor) []string {
	var chips []string
	for severity := range severityTheme {
		level := model.Severity(severity)
		st := severityStyle(level)
		if !floor.Keeps(level) {
			st = mutedStyle
		}
		chips = append(chips, st.seq().Render("● "+level.String()))
	}
	if floor != model.FloorAll {
		chips = append(chips, mutedStyle.seq().Render("showing ≥ "+floor.String()))
	}
	return chips
}

// fact is one labeled row of the masthead: a plain value the block wraps and
// paints, or ready-made chips (the severity key) it lays out whole. A full fact
// spans the line instead of taking one of the two columns.
type fact struct {
	label string
	value string
	chips []string
	styl  style
	full  bool
}

// factGrid lays a fact block out inside a text width: two facts to a row while
// the line has room for both, one when it does not, every label in the block's
// label column and every value starting in its own column. A value too long for
// the rest of its column wraps under its own label. The label column is as wide
// as the longest label, so the block reads as a table.
func factGrid(facts []fact, width int) []string {
	var grid, spanning []fact
	labelWidth := 0
	for _, f := range facts {
		if len(f.chips) == 0 && f.value == "" {
			continue
		}
		labelWidth = max(labelWidth, lipgloss.Width(f.label))
		if f.full {
			spanning = append(spanning, f)
			continue
		}
		grid = append(grid, f)
	}
	inner := width
	columns, widths := 1, []int{inner}
	if two := (inner - factColumnGap) / 2; two-labelWidth-factGap >= factMinValue {
		columns, widths = 2, []int{two, inner - two - factColumnGap}
		if tight := tightColumns(grid, labelWidth, widths); tight != nil {
			widths = tight
		}
	}

	var rows []string
	for start := 0; start < len(grid); start += columns {
		cells := make([][]string, 0, columns)
		for col := range columns {
			if start+col >= len(grid) {
				break
			}
			cells = append(cells, grid[start+col].lines(max(widths[col]-labelWidth-factGap, 1)))
		}
		height := 0
		for _, lines := range cells {
			height = max(height, len(lines))
		}
		for line := range height {
			var row strings.Builder
			for col, lines := range cells {
				cell := factCell(grid[start+col].label, labelWidth, lines, line)
				if col < len(cells)-1 {
					cell = padTo(cell, widths[col]+factColumnGap)
				}
				row.WriteString(cell)
			}
			rows = append(rows, row.String())
		}
	}
	for _, f := range spanning {
		for index, line := range f.lines(max(inner-labelWidth-factGap, 1)) {
			label := ""
			if index == 0 {
				label = mutedStyle.seq().Render(padRight(f.label, labelWidth)) + strings.Repeat(" ", factGap)
			} else {
				label = strings.Repeat(" ", labelWidth+factGap)
			}
			rows = append(rows, label+line)
		}
	}
	return rows
}

// factCell is one line of one cell: the label on the cell's first line, the
// value's own line after it, and the continuation lines aligned under the value.
func factCell(label string, labelWidth int, lines []string, index int) string {
	if index >= len(lines) {
		return ""
	}
	if index == 0 {
		return mutedStyle.seq().Render(padRight(label, labelWidth)) +
			strings.Repeat(" ", factGap) + lines[0]
	}
	return strings.Repeat(" ", labelWidth+factGap) + lines[index]
}

// tightColumns narrows the two columns to the widths their own content asks for,
// so a wide terminal does not leave the two facts of a row an ocean apart. Each
// value is measured as the lines it already wraps to inside its half of the
// line, so tightening never re-breaks a value; nil when the narrowed columns do
// not both fit inside the strip the halves came from.
func tightColumns(grid []fact, labelWidth int, widths []int) []int {
	room := factStrip(widths)
	tight := make([]int, len(widths))
	for index, f := range grid {
		column := index % len(widths)
		for _, line := range f.lines(max(widths[column]-labelWidth-factGap, 1)) {
			tight[column] = max(tight[column], labelWidth+factGap+lipgloss.Width(line))
		}
	}
	if factStrip(tight) > room {
		return nil
	}
	return tight
}

// factStrip is the line a set of columns occupies: their widths plus the gaps
// between them.
func factStrip(widths []int) int {
	total := factColumnGap * (len(widths) - 1)
	for _, width := range widths {
		total += width
	}
	return total
}

// padTo pads a rendered cell out to the next column's start, keeping at least
// one column of separation when the cell overran its column.
func padTo(cell string, width int) string {
	return cell + strings.Repeat(" ", max(width-lipgloss.Width(cell), 1))
}

// lines is one fact's value as the lines it occupies: the chips laid out whole,
// or the plain value wrapped.
func (f fact) lines(width int) []string {
	if len(f.chips) > 0 {
		return wrapChips(f.chips, width)
	}
	lines := strings.Split(boundRow(f.value, width), "\n")
	for index, line := range lines {
		lines[index] = f.styl.seq().Render(line)
	}
	return lines
}

// wrapChips lays painted items out across the line: an item that does not fit
// goes whole to the next line.
func wrapChips(chips []string, width int) []string {
	var rows []string
	line := ""
	for _, chip := range chips {
		switch {
		case line == "":
			line = chip
		case lipgloss.Width(line)+factGap+lipgloss.Width(chip) <= width:
			line += strings.Repeat(" ", factGap) + chip
		default:
			rows = append(rows, line)
			line = chip
		}
	}
	if line != "" {
		rows = append(rows, line)
	}
	return rows
}

// padRight pads a band cell or a fact label to a column width.
func padRight(text string, width int) string {
	if pad := width - lipgloss.Width(text); pad > 0 {
		return text + strings.Repeat(" ", pad)
	}
	return text
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
// the line unchanged.
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
	if lipgloss.Width(row) <= width {
		return row
	}
	wrapped := xansi.Wordwrap(row, width, "/")
	if lipgloss.Width(wrapped) <= width {
		return wrapped
	}
	return xansi.Hardwrap(wrapped, width, false)
}

// checkPanel is one check's display panel. With a body it is a rail panel;
// without a body but with a note (timeout/failure) it is a thin grey rail
// panel. A collected check without signals and a check that was never
// collected both return an empty string, and the caller stays silent: the
// report only presents evidence, and a missing command belongs to the target's
// environment and does not enter the report.
// panelRenderer is the rendering entry point; being a variable gives the
// fallback chain a panic source it can control.
var panelRenderer = checkPanel

func checkPanel(result *model.CheckResult, maxLines, width int) string {
	rows := bodyRows(result, maxLines, width)
	rows = append(rows, stderrRows(result.Stderr)...)
	if len(rows) > 0 {
		return checkBlock(topSeverity(result.Document), checkHead(result, width), rows, width)
	}
	if result.Outcome == model.Skipped {
		return ""
	}
	if result.Note != "" {
		return thinRailPanel(result, result.Note, maxLines, width)
	}
	return ""
}

// thinRailPanel is the quiet grey rail: the check id as the band label on the
// left, one red note on the right, raw text underneath — the shape shared by a
// failed check and a failed render.
func thinRailPanel(result *model.CheckResult, note string, maxLines, width int) string {
	head := bandHead(subBandFill, subBandStyle.Render(strings.ToUpper(result.Check.ID)), note,
		style{fg: "9", bold: true, bg: subBandColor}, railInner(width))
	return checkBlock(model.Info, head, plainRows(result.Raw, result.Stderr, maxLines), width)
}

// checkHead is the panel's title band: the check id as the level-two heading
// label (uppercase, the same step as the listing's aspect bands), metadata on
// the right.
func checkHead(result *model.CheckResult, width int) []string {
	return bandHead(subBandFill, subBandStyle.Render(strings.ToUpper(result.Check.ID)), metaParts(result),
		style{fg: bandMetaColor, bg: subBandColor}, railInner(width))
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

// renderPanel renders one check panel, falling back step by step on a
// rendering panic: first to fallbackPanel's grey rail with the raw text, and if
// even that cannot be drawn, failed=true with empty text so the caller prints
// plain text.
func renderPanel(result *model.CheckResult, maxLines, width int) (text string, failed bool) {
	defer func() {
		if recover() != nil {
			text, failed = fallbackPanel(result, maxLines, width), true
		}
	}()
	return panelRenderer(result, maxLines, width), false
}

// fallbackPanel is the fallback panel: check id, failure note, and raw text
// (plain, wrapped to the budget) on a thin grey rail. If it panics in turn it
// returns an empty string.
func fallbackPanel(result *model.CheckResult, maxLines, width int) (text string) {
	defer func() {
		if recover() != nil {
			text = ""
		}
	}()
	return thinRailPanel(result, "render failed, showing raw output", maxLines, width)
}

// plainRows are raw rows: the final fallback for a failed render, folded to the
// budget.
func plainRows(raw, stderr string, limit int) []string {
	limit = max(limit, 1)
	var rows []string
	if raw != "" {
		body := textutil.CollectLines(strings.Trim(raw, "\r\n"))
		cut := min(len(body), limit)
		rows = append(rows, body[:cut]...)
		if cut < len(body) {
			rows = append(rows, fmt.Sprintf("… %d lines omitted", len(body)-cut))
		}
	}
	for _, line := range textutil.CollectLines(strings.TrimSpace(stderr)) {
		if line != "" {
			rows = append(rows, line)
		}
	}
	return rows
}

// sectionSeverity is one section's highest hit severity, counting hits on the
// section title; Info when there is no signal.
func sectionSeverity(section model.Section) model.Severity {
	severity := model.Info
	for _, match := range section.TitleMatches {
		if match.Severity.IsSignal() && match.Severity < severity {
			severity = match.Severity
		}
	}
	for _, line := range section.Lines {
		if line.Severity.IsSignal() && line.Severity < severity {
			severity = line.Severity
		}
	}
	return severity
}

// topSeverity is the whole panel's highest hit severity; Info when there is no
// hit.
func topSeverity(document model.Document) model.Severity {
	severity := model.Info
	for _, section := range document.Sections {
		if section := sectionSeverity(section); section.IsSignal() && section < severity {
			severity = section
		}
	}
	return severity
}

// metaParts is the metadata on the right of the panel's first line: the probe
// chain when a fallback happened, the number of filtered lines, and the
// truncation mark.
func metaParts(result *model.CheckResult) string {
	var parts []string
	if len(result.SkippedLabels) > 0 {
		chain := slices.Concat(result.SkippedLabels, []string{result.ProbeLabel})
		parts = append(parts, strings.Join(chain, " → "))
	}
	if filtered := lo.SumBy(result.Document.Filtered, func(fc model.FilterCount) int { return fc.Count }); filtered > 0 {
		parts = append(parts, fmt.Sprintf("filtered %d", filtered))
	}
	if result.Document.Truncated {
		parts = append(parts, "truncated")
	}
	return strings.Join(parts, " · ")
}

// stderrRows appends the stderr of a non-zero exit after the body, in the
// default color and exempt from the rules.
func stderrRows(stderr string) []string {
	trimmed := strings.TrimSpace(stderr)
	if trimmed == "" {
		return nil
	}
	return textutil.CollectLines(trimmed)
}

// bodyRows is the panel body: source title rows plus raw rows, with one blank
// line between sources.
// --max-lines is the whole check's budget, shared across sources, counting
// quiet rows only; finding rows and their context are always printed, omitted
// rows collapse into a count, and once the budget is gone, sources without a
// hit are dropped entirely. term is the terminal width; body rows are laid out
// to the text width inside the rail.
func bodyRows(result *model.CheckResult, maxLines, term int) []string {
	width := textWidth(term)
	base := newLineStyler(result.Check.Syntax)
	var rows []string
	budget := maxLines
	for _, section := range result.Document.Sections {
		// A section override builds its own instance: cross-line state (table
		// anchors) must not leak across sections or shapes.
		lineStyler := base
		if syntax := sectionSyntax(result.Check, section.Title); syntax != result.Check.Syntax {
			lineStyler = newLineStyler(syntax)
		}
		planned, used := plan(section.Lines, budget)
		// A section the reading layer kept for its title alone — every row was
		// filtered or below the floor — is still a finding: the title is what
		// the rule matched. Skipping it here would print nothing for it.
		if planned == nil && len(section.TitleMatches) == 0 {
			continue
		}
		budget -= used
		if len(rows) > 0 {
			rows = append(rows, "")
		}
		if section.Title != "" {
			rows = append(rows, sourceTitle(section, width)...)
		}
		rows = append(rows, plannedRows(section.Lines, planned, lineStyler, width)...)
	}
	return rows
}

// sectionSyntax resolves one section's syntax: the first SectionSyntax entry
// whose title glob matches wins, other sections keep the check's syntax.
func sectionSyntax(check *model.Check, title string) model.Syntax {
	for _, override := range check.SectionSyntax {
		if ok, _ := path.Match(override.Title, title); ok {
			return override.Syntax
		}
	}
	return check.Syntax
}

// sourceTitle is a source title row: bold plain (default color), hit spans in
// their severity color, the reason ⟨…⟩ at the end, moved to its own line
// aligned with the body when it does not fit.
func sourceTitle(section model.Section, width int) []string {
	spans := []Span{{Start: 0, End: len(section.Title), Style: style{bold: true}}}
	spans = append(spans, hitSpans(section.TitleMatches)...)
	return withReason(paintLine(section.Title, spans), section.TitleMatches, width)
}

// plannedRows emits rows as planned: visible rows render the body, omitted rows
// collapse into one counted gap.
func plannedRows(lines []model.Line, sequence []linePlan, lineStyler LineStyler, width int) []string {
	var rows []string
	for _, item := range sequence {
		if item.visible {
			rows = append(rows, lineRows(lines[item.index], lineStyler, width)...)
			continue
		}
		rows = append(rows, style{faint: true, italic: true}.seq().Render(
			fmt.Sprintf("… %d lines", item.count)))
	}
	return rows
}

// plan decides which rows are printed. It returns the (visible, row index or
// omitted count) sequence and the quiet-row budget spent.
//
// Finding rows and the row on either side are always printed and do not spend
// budget; the rest is taken in text order from the top until the budget runs
// out. Consecutive omitted rows collapse into one counted gap. It returns nil
// when no row is kept.
func plan(lines []model.Line, budget int) ([]linePlan, int) {
	keep := make([]bool, len(lines))
	kept := 0
	for index, line := range lines {
		if line.Severity.IsSignal() {
			for _, around := range [3]int{index - 1, index, index + 1} {
				if 0 <= around && around < len(lines) && !keep[around] {
					keep[around] = true
					kept++
				}
			}
		}
	}
	used := 0
	for index := range lines {
		if keep[index] || used >= budget {
			continue
		}
		keep[index] = true
		kept++
		used++
	}
	if kept == 0 {
		return nil, 0
	}
	var sequence []linePlan
	index := 0
	for index < len(lines) {
		if keep[index] {
			sequence = append(sequence, linePlan{visible: true, index: index})
			index++
			continue
		}
		start := index
		for index < len(lines) && !keep[index] {
			index++
		}
		sequence = append(sequence, linePlan{visible: false, count: index - start})
	}
	return sequence, used
}

type linePlan struct {
	visible bool
	index   int
	count   int
}

// lineRows is one body row: findings show up as painted spans and a trailing
// reason, with no bullet.
func lineRows(line model.Line, lineStyler LineStyler, width int) []string {
	return withReason(lineText(line, lineStyler), line.Matches, width)
}

// lineText renders one line: syntax coloring goes down first and hit spans
// cover it; comments are not filtered (important information may hide in them)
// but are painted muted to set them apart.
func lineText(line model.Line, lineStyler LineStyler) string {
	var spans []Span
	if lineStyler != nil {
		spans = append(spans, lineStyler(line.Text)...)
	}
	hits := hitSpans(line.Matches)
	spans = append(spans, hits...)
	if len(hits) == 0 && commentLine.MatchString(line.Text) {
		spans = append(spans, Span{Start: 0, End: len(line.Text), Style: mutedStyle})
	}
	return paintLine(line.Text, spans)
}

// hitSpans paints a line's signal matches, most severe last. Spans stack in
// order, so where two rules cover the same text the more severe one wins — the
// span the trailing reason names, rather than whichever rule happened to be
// declared later.
func hitSpans(matches []model.Match) []Span {
	signals := lo.Filter(matches, func(match model.Match, _ int) bool {
		return match.Severity.IsSignal()
	})
	slices.SortStableFunc(signals, func(a, b model.Match) int {
		return cmp.Compare(b.Severity, a.Severity)
	})
	return lo.Map(signals, func(match model.Match, _ int) Span {
		return Span{Start: match.Start, End: match.End, Style: severityStyle(match.Severity)}
	})
}

// withReason appends the reason ⟨…⟩ of the highest hit severity at the end of
// the row; when it does not fit it goes on its own line aligned with the body.
func withReason(row string, matches []model.Match, width int) []string {
	var top model.Match
	signals := 0
	for _, match := range matches {
		if !match.Severity.IsSignal() {
			continue
		}
		if signals == 0 || match.Severity < top.Severity {
			top = match
		}
		signals++
	}
	if signals == 0 {
		return []string{row}
	}
	reason := "⟨" + top.Message + "⟩"
	if signals > 1 {
		reason += fmt.Sprintf(" +%d", signals-1)
	}
	reasonSt := style{faint: true}.seq().Render(reason)
	if lipgloss.Width(row)+2+lipgloss.Width(reason) <= width {
		return []string{row + "  " + reasonSt}
	}
	return []string{row, reasonSt}
}

// LiveObserver is the live observer: one progress line plus check panels
// released in catalog order, with an aspect banner drawn first when the aspect
// changes.
//
// One goroutine owns the terminal and all of the observer's state: the runner's
// workers only send events (CheckStarted and CheckFinished enqueue and never
// touch the writer), the ticker feeds the same queue, and nothing needs a lock.
// A finished check is taken into a table first and written back only when the
// catalog prefix is complete; a slow check ahead of it lets later ones pile up.
type LiveObserver struct {
	w        io.Writer
	maxLines int
	width    int
	tty      bool

	order    map[*model.Check]int
	events   chan observerEvent
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}

	received map[int]*model.CheckResult
	next     int
	aspect   string

	total    int
	finished int
	current  string
	started  time.Time
	frame    int
}

// observerEvent is one message to the render loop.
type observerEvent struct {
	kind   eventKind
	check  *model.Check
	result *model.CheckResult
}

type eventKind int

const (
	startedEvent eventKind = iota
	finishedEvent
)

// progressInterval is the progress line's refresh cadence.
const progressInterval = 100 * time.Millisecond

// NewLiveObserver builds the observer. With tty false no progress line is
// drawn and panels are emitted in order.
func NewLiveObserver(w io.Writer, checks []*model.Check, maxLines, width int, tty bool) *LiveObserver {
	order := make(map[*model.Check]int, len(checks))
	for index, check := range checks {
		order[check] = index
	}
	return &LiveObserver{
		w:        w,
		maxLines: maxLines,
		width:    width,
		tty:      tty,
		order:    order,
		events:   make(chan observerEvent, 2*len(checks)+1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		received: map[int]*model.CheckResult{},
		total:    len(checks),
		started:  time.Now(),
	}
}

// Start launches the render loop.
func (o *LiveObserver) Start() {
	go o.loop()
}

// loop is the single owner of the terminal and the observer state: events
// apply here and nowhere else, so there is nothing to lock.
func (o *LiveObserver) loop() {
	defer func() {
		if o.tty { // the progress line leaves nothing behind
			fmt.Fprint(o.w, "\r\033[K")
		}
		close(o.done)
	}()
	var ticks <-chan time.Time
	if o.tty {
		ticker := time.NewTicker(progressInterval)
		defer ticker.Stop()
		ticks = ticker.C
	}
	for {
		select {
		case <-o.stop:
			o.drain()
			return
		case event := <-o.events:
			o.apply(event)
		case <-ticks:
			o.drawProgress()
		}
	}
}

// drain applies everything still queued: Close may fire while panels wait,
// and those panels are still due.
func (o *LiveObserver) drain() {
	for {
		select {
		case event := <-o.events:
			o.apply(event)
		default:
			return
		}
	}
}

func (o *LiveObserver) apply(event observerEvent) {
	switch event.kind {
	case startedEvent:
		o.current = string(event.check.Aspect) + " · " + event.check.ID
		o.drawProgress()
	case finishedEvent:
		o.finished++
		o.received[o.order[event.check]] = event.result
		o.flush()
	}
}

// CheckStarted queues the progress update.
func (o *LiveObserver) CheckStarted(check *model.Check) {
	o.events <- observerEvent{kind: startedEvent, check: check}
}

// CheckFinished queues the result; the loop releases the panels that are ready
// in catalog order.
func (o *LiveObserver) CheckFinished(check *model.Check, result *model.CheckResult) {
	o.events <- observerEvent{kind: finishedEvent, check: check, result: result}
}

// Close stops the loop and waits until every queued panel is on the wire. Call
// it after the run has joined, when no more events can arrive — the queue
// holds two events per check, so the send side never blocks.
func (o *LiveObserver) Close() {
	o.stopOnce.Do(func() { close(o.stop) })
	<-o.done
}

func (o *LiveObserver) flush() {
	for {
		result, ok := o.received[o.next]
		if !ok {
			return
		}
		delete(o.received, o.next)
		o.next++
		o.emit(result)
	}
}

func (o *LiveObserver) emit(result *model.CheckResult) {
	text, failed := renderPanel(result, o.maxLines, o.width)
	if text == "" && !failed { // no signal: stay silent
		return
	}
	// The progress line holds the current row; erase it before writing the
	// panel, or the spinner glyphs stick to the rail's first line.
	if o.tty {
		fmt.Fprint(o.w, "\r\033[K")
	}
	if aspect := string(result.Check.Aspect); aspect != o.aspect {
		o.aspect = aspect
		fmt.Fprintln(o.w, headingBand(aspect, o.width))
	}
	if text == "" {
		// Not even the fallback panel can be drawn: bare text with the check
		// name, rather than silently swallowing this check
		fmt.Fprintln(o.w, result.Check.ID+"  render failed")
		for _, row := range plainRows(result.Raw, result.Stderr, o.maxLines) {
			fmt.Fprintln(o.w, row)
		}
	} else {
		fmt.Fprintln(o.w, text)
	}
	fmt.Fprintln(o.w)
	o.drawProgress()
}

func (o *LiveObserver) drawProgress() {
	if !o.tty {
		return
	}
	frame := spinnerFrames[o.frame%len(spinnerFrames)]
	o.frame++
	line := fmt.Sprintf("\r\033[K%s %d/%d %s %s",
		accentStyle.seq().Render(frame),
		o.finished, o.total,
		mutedStyle.seq().Render(o.current),
		mutedStyle.seq().Render(time.Since(o.started).Round(time.Second).String()))
	fmt.Fprint(o.w, line)
}
