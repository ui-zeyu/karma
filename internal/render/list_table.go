// The `karma list` catalog view: a two-level heading tree — one band per
// platform, one band per aspect — over rows that carry aligned id, title, and
// probe-chain columns.
//
// The headings replace the platform/aspect cells of a plain grid: the platform
// is said once per platform, the aspect once per group, and every row keeps the
// rest of the line for its title. Column widths are measured over the whole
// selection, so the groups line up with each other; an over-long title wraps
// inside its own column and the columns to its right stay put.

package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	xansi "github.com/charmbracelet/x/ansi"

	"karma/internal/model"
)

// Column geometry: the rows' indent under the heading bands, two columns of gap
// between columns, a title floor, and the probe chain's floor (its natural
// width is driven by the longest fallback chain in the catalog, which would
// otherwise starve the title column).
const (
	listRowIndent  = 2 // rows sit one level in from the heading bands
	listGap        = 2
	listTitleFloor = 24
	listTitleShare = 5 // the title targets two fifths of the line
	listChainFloor = 18
)

// listGroup is one platform/aspect run of the catalog.
type listGroup struct {
	platform model.Platform
	aspect   model.Aspect
	checks   []*model.Check
}

// RenderListTable draws the catalog (both platforms merged, told apart by the
// platform band). The width comes from the caller (terminal width or a fallback).
func RenderListTable(w io.Writer, selected []*model.Check, width int) {
	if len(selected) == 0 {
		return
	}
	idW, titleW, chainW := listLayout(selected, width)
	groups := groupChecks(selected)
	for index, group := range groups {
		if index == 0 || groups[index-1].platform != group.platform {
			if index > 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w, bandHeading(string(group.platform), width, bandStyle))
		}
		fmt.Fprintln(w, bandHeading(string(group.aspect), width, subBandStyle))
		for _, check := range group.checks {
			fmt.Fprintln(w, listRow(check, idW, titleW, chainW))
		}
	}
}

// bandHeading is one heading of the listing's tree: a full-width band in the
// given step, so the platform and the aspect are each said once instead of once
// per group.
func bandHeading(name string, term int, st lipgloss.Style) string {
	return fillBand(" "+strings.ToUpper(name), lineWidth(term), st)
}

// listLayout splits the line between the three columns: the id keeps its natural
// width (it is the selector vocabulary), the title takes two fifths, and the
// chain gets the rest. A line too narrow for both drops the chain, which is
// metadata; nothing ever exceeds the line.
func listLayout(selected []*model.Check, width int) (idW, titleW, chainW int) {
	line := lineWidth(width)
	idW, chainNat := listColumnWidths(selected)
	rest := line - (listRowIndent + idW + listGap)
	titleW = min(max(line*2/listTitleShare, listTitleFloor), rest)
	if rest-titleW-listGap < listChainFloor {
		return idW, max(rest, 1), 0
	}
	return idW, titleW, min(chainNat, rest-titleW-listGap)
}

// groupChecks folds the selection (already in catalog order) into consecutive
// platform/aspect runs; nothing is reordered.
func groupChecks(selected []*model.Check) []listGroup {
	groups := make([]listGroup, 0, len(selected))
	for _, check := range selected {
		last := len(groups) - 1
		if last < 0 || groups[last].platform != check.Platform || groups[last].aspect != check.Aspect {
			groups = append(groups, listGroup{platform: check.Platform, aspect: check.Aspect})
			last++
		}
		groups[last].checks = append(groups[last].checks, check)
	}
	return groups
}

// listColumnWidths measures the two narrow columns over the whole selection, so
// every group's rows align.
func listColumnWidths(selected []*model.Check) (idW, chainW int) {
	for _, check := range selected {
		idW = max(idW, lipgloss.Width(check.ID))
		chainW = max(chainW, lipgloss.Width(probeChain(check)))
	}
	return idW, chainW
}

// probeChain is the fallback chain as displayed: probe labels joined by arrows.
func probeChain(check *model.Check) string {
	labels := make([]string, 0, len(check.Probes))
	for _, probe := range check.Probes {
		labels = append(labels, probe.Label)
	}
	return strings.Join(labels, " → ")
}

// listRow is one catalog row: indented blue id, title in the default color, and
// the muted probe chain starting at a fixed column. Only the two sized cells
// carry a width (the id pads to its column, the title and chain wrap inside
// theirs), and the padding after the last visible character is trimmed.
func listRow(check *model.Check, idW, titleW, chainW int) string {
	id := lipgloss.NewStyle().Foreground(listIDColor).
		Padding(0, listGap, 0, listRowIndent).Width(listRowIndent + idW + listGap).
		Render(check.ID)
	title := lipgloss.NewStyle().Width(titleW).Render(wordWrap(check.Title, titleW))
	if chainW == 0 {
		return trimLineEnds(lipgloss.JoinHorizontal(lipgloss.Top, id, title))
	}
	chain := lipgloss.NewStyle().Foreground(MutedColor).Width(chainW).
		Render(wordWrap(probeChain(check), chainW))
	cells := lipgloss.JoinHorizontal(lipgloss.Top, id, title,
		lipgloss.NewStyle().Width(listGap).Render(""), chain)
	return trimLineEnds(cells)
}

// wordWrap breaks a cell's text between words; a slash counts as a break point
// so a run of paths (Sunlogin/ToDesk/…) wraps between components instead of
// splitting a word. A single token wider than the column is left to the cell's
// own hard wrap.
func wordWrap(text string, limit int) string {
	if limit < 1 {
		return text
	}
	return xansi.Wordwrap(text, limit, "/")
}

// trimLineEnds drops the blank padding at the end of each joined line (a
// wrapped cell leaves its shorter neighbours padded).
func trimLineEnds(block string) string {
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " ")
	}
	return strings.Join(lines, "\n")
}
