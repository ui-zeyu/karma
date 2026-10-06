// The report's masthead: the level-one band with the byline, the level-two head
// carrying the build's version, the run's clock, and the fact grid under it.
// The command-line skeleton's help screen wears the same first panel.

package render

import (
	"cmp"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"karma/internal/model"
)

// The masthead's labeled facts: a value starts a two-column gap after its
// label, and a second column starts a four-column gap after the first.
// factMinValue is the narrowest value column worth a second column.
const (
	factGap       = 2
	factColumnGap = 4
	factMinValue  = 18
)

// HeaderInfo is what the masthead says beyond the host facts: how the run
// reached the target, when it started, and how much of the catalog it covers.
type HeaderInfo struct {
	Channel   string    // the channel and what it reaches: "local", "ssh root@host:22"
	Version   string    // the build's version
	Started   time.Time // when collection began
	Selected  int       // checks this run collects
	Total     int       // checks the platform's catalog holds
	Selectors []string  // the run's selector words, empty for the whole catalog
	Floor     model.SeverityFloor
}

// RenderHeader draws the report's masthead: the KARMA band — the same
// full-width level-one strip an aspect banner wears, covering the rail's own
// column, with the author on its right edge — over a rail panel whose head band
// is the level-two step every check title wears, carrying the build's version
// and the run's clock. Below it the facts line up as a table: which host,
// reached how, running what, collected by whom, and how much of the catalog
// this run covers.
func RenderHeader(w io.Writer, facts model.HostFacts, info HeaderInfo, term int) {
	head := bandHead(subBandFill, subBandStyle.Render(info.Version), clock(info.Started),
		style{fg: bandMetaColor, bg: subBandColor}, railInner(term))
	body := factGrid(mastheadFacts(facts, info), textWidth(term))
	fmt.Fprintln(w, mastheadBand(term))
	fmt.Fprintln(w, checkBlock(model.Info, head, body, term))
	fmt.Fprintln(w)
}

// authorLabel is the report's byline, written on the right edge of the
// masthead's level-one band the way every panel head carries its metadata.
const authorLabel = "yuyy"

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
