// One check's panel: the display budget, the section titles, the row planning
// and the span painting. The rail block itself is in render.go.

package render

import (
	"cmp"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/samber/lo"

	"karma/internal/fault"
	"karma/internal/form"
	"karma/internal/model"
	"karma/internal/textutil"
)

// Comment lines are not filtered (important information may hide in them) and
// are painted muted instead.
var commentLine = regexp.MustCompile(`^[ \t]*#`)

// panelRenderer is the rendering entry point; being a variable gives the
// fallback chain a panic source it can control.
var panelRenderer = checkPanel

// checkPanel is one check's display panel. With a body it is a rail panel;
// without a body but with a note (timeout/failure) it is a thin grey rail
// panel. A collected check without signals and a check that was never
// collected both return an empty string, and the caller stays silent: the
// report only presents evidence, and a missing command belongs to the target's
// environment and does not enter the report. color says whether the stream is a
// terminal: without it the panel is the same layout with no escapes.
func checkPanel(result *model.CheckResult, maxLines, term int, color bool) string {
	rows := bodyRows(result, maxLines, term, color)
	rows = append(rows, stderrRows(result.Stderr)...)
	if len(rows) > 0 {
		return checkBlock(topSeverity(result.Document), checkHead(result, term), rows, term)
	}
	if result.Outcome == model.Skipped {
		return ""
	}
	if result.Note != "" {
		return thinRailPanel(result, result.Note, maxLines, term)
	}
	return ""
}

// thinRailPanel is the quiet grey rail: the check id as the band label on the
// left, one red note on the right, raw text underneath — the shape shared by a
// failed check and a failed render.
func thinRailPanel(result *model.CheckResult, note string, maxLines, term int) string {
	head := bandHead(subBandFill, subBandStyle.Render(strings.ToUpper(result.Check.ID)), note,
		style{FG: "9", Bold: true, BG: string(subBandColor)}, railInner(term))
	return checkBlock(model.Info, head, plainRows(result.Raw, result.Stderr, maxLines), term)
}

// checkHead is the panel's title band: the check id as the level-two heading
// label (uppercase, the same step as the listing's aspect bands), metadata on
// the right.
func checkHead(result *model.CheckResult, term int) []string {
	return bandHead(subBandFill, subBandStyle.Render(strings.ToUpper(result.Check.ID)), metaParts(result),
		style{FG: string(bandMetaColor), BG: string(subBandColor)}, railInner(term))
}

// renderPanel renders one check panel, falling back step by step on a
// rendering panic: first to fallbackPanel's grey rail with the raw text, and if
// even that cannot be drawn, failed=true with empty text so the caller prints
// plain text. Each step is a boundary of the fault package, like every other
// one a run crosses.
func renderPanel(result *model.CheckResult, maxLines, term int, color bool) (string, bool) {
	text, err := fault.Result("panel "+result.Check.ID, func() string {
		return panelRenderer(result, maxLines, term, color)
	})
	if err == nil {
		return text, false
	}
	fallback, _ := fault.Result("panel fallback", func() string {
		return fallbackPanel(result, maxLines, term)
	})
	return fallback, true
}

// fallbackPanel is the fallback panel: check id, failure note, and raw text
// (plain, wrapped to the budget) on a thin grey rail.
func fallbackPanel(result *model.CheckResult, maxLines, term int) string {
	return thinRailPanel(result, "render failed, showing raw output", maxLines, term)
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

// bodyRows is the panel body: section title rows plus raw rows, with one blank
// line between sections.
// --max-lines is the whole check's budget, shared across sections, counting
// quiet rows only; finding rows and their context are always printed, omitted
// rows collapse into a count, and once the budget is gone, sections without a
// hit are dropped entirely. term is the terminal width; body rows are laid out
// to the text width inside the rail. A section whose body arrived as records is
// drawn in the shape its check declares; every other section reads as text.
func bodyRows(result *model.CheckResult, maxLines, term int, color bool) []string {
	width := textWidth(term)
	// A stream that takes no color pays for no lexing: every span a syntax
	// produces would be painted through a style whose profile writes no
	// escapes, so the line would come back as the bytes it went in as. The
	// forms make the same decision from the same flag.
	var base lineStyler
	if color {
		base = newLineStyler(result.Check.Syntax)
	}
	var rows []string
	budget := maxLines
	for _, section := range result.Document.Sections {
		// A section override builds its own instance: cross-line state (table
		// anchors) must not leak across sections or shapes.
		lineStyler := base
		if syntax := sectionSyntax(result.Check, section.Title); color && syntax != result.Check.Syntax {
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
			rows = append(rows, sectionTitle(section, width)...)
		}
		if block, ok := formBlock(result.Check.Form, section, planned); ok {
			rows = append(rows, result.Check.Form.Render(block, model.RenderOptions{Width: width, Color: color})...)
			continue
		}
		rows = append(rows, plannedRows(section.Lines, planned, lineStyler, width)...)
	}
	return rows
}

// formBlock is one section's records as the block a form lays out: the head
// from the record set, one item per planned line, and a counted gap where the
// display budget hid rows. ok is false when this section is not all records —
// a form-less check, or a body the shaper declined — and the caller then draws
// the section as text.
func formBlock(form model.Form, section model.Section, planned []linePlan) (model.Block, bool) {
	if form == nil || len(section.Columns) == 0 {
		return model.Block{}, false
	}
	for _, line := range section.Lines {
		if line.Record == nil {
			return model.Block{}, false
		}
	}
	block := model.Block{Header: section.Columns}
	for _, item := range planned {
		if !item.visible {
			block.Items = append(block.Items, model.BlockItem{
				Note: fmt.Sprintf("… %d lines", item.count)})
			continue
		}
		line := section.Lines[item.index]
		block.Items = append(block.Items, model.BlockItem{
			Rec: line.Record, Matches: line.Matches})
	}
	return block, true
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

// sectionTitle is a section title row: bold plain (default color), hit spans in
// their severity color, the reason ⟨…⟩ at the end, moved to its own line
// aligned with the body when it does not fit.
func sectionTitle(section model.Section, width int) []string {
	spans := []paintSpan{{Start: 0, End: len(section.Title), Style: style{Bold: true}}}
	spans = append(spans, hitSpans(section.Title, section.TitleMatches)...)
	return withReason(paintLine(section.Title, spans), section.TitleMatches, width)
}

// plannedRows emits rows as planned: visible rows render the body, omitted rows
// collapse into one counted gap.
func plannedRows(lines []model.Line, sequence []linePlan, lineStyler lineStyler, width int) []string {
	var rows []string
	for _, item := range sequence {
		if item.visible {
			rows = append(rows, lineRows(lines[item.index], lineStyler, width)...)
			continue
		}
		rows = append(rows, style{Faint: true, Italic: true}.Render(
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
func lineRows(line model.Line, lineStyler lineStyler, width int) []string {
	return withReason(lineText(line, lineStyler), line.Matches, width)
}

// lineText renders one line: syntax coloring goes down first and hit spans
// cover it; comments are not filtered (important information may hide in them)
// but are painted muted to set them apart.
func lineText(line model.Line, lineStyler lineStyler) string {
	var spans []paintSpan
	if lineStyler != nil {
		spans = append(spans, lineStyler(line.Text)...)
	}
	hits := hitSpans(line.Text, line.Matches)
	spans = append(spans, hits...)
	if len(hits) == 0 && commentLine.MatchString(line.Text) {
		spans = append(spans, paintSpan{Start: 0, End: len(line.Text), Style: mutedStyle})
	}
	return paintLine(line.Text, spans)
}

// hitSpans paints a line's signal matches, most severe last. Spans stack in
// order, so where two rules cover the same text the more severe one wins — the
// span the trailing reason names, rather than whichever rule happened to be
// declared later. A line of text is a one-field record, so the spans sit in the
// line's own coordinates already; a hit that belongs to the record paints the
// whole line.
func hitSpans(text string, matches []model.Match) []paintSpan {
	signals := lo.Filter(matches, func(match model.Match, _ int) bool {
		return match.Severity.IsSignal()
	})
	slices.SortStableFunc(signals, func(a, b model.Match) int {
		return cmp.Compare(b.Severity, a.Severity)
	})
	var spans []paintSpan
	for _, match := range signals {
		if len(match.Spans) == 0 {
			spans = append(spans, paintSpan{Start: 0, End: len(text), Style: severityStyle(match.Severity)})
			continue
		}
		for _, span := range match.Spans {
			if span.Field != 0 {
				continue
			}
			spans = append(spans, paintSpan{Start: span.Start, End: span.End, Style: severityStyle(match.Severity)})
		}
	}
	return spans
}

// withReason appends the reason ⟨…⟩ of the highest hit severity at the end of
// the row; when it does not fit it goes on its own line aligned with the body.
func withReason(row string, matches []model.Match, width int) []string {
	reason := form.ReasonFor(matches)
	if reason == "" {
		return []string{row}
	}
	reasonSt := style{Faint: true}.Render(reason)
	if lipgloss.Width(row)+2+lipgloss.Width(reason) <= width {
		return []string{row + "  " + reasonSt}
	}
	return []string{row, reasonSt}
}
