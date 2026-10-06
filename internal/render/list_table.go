// The `karma list` catalog view: a two-level heading tree — one full-width band
// per platform, one rail panel per aspect — over rows that carry aligned id,
// title, and probe-chain columns.
//
// The headings replace the platform/aspect cells of a plain grid: the platform
// is said once per platform, the aspect once per group. Each aspect group is
// drawn as the same panel as a report check — the muted half-block rail and the
// level-two title band — so the heading tree reads as the same element in both
// views. Column widths are measured over the whole selection, so the groups
// line up with each other; an over-long title wraps inside its own column and
// the columns to its right stay put.

package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	xansi "github.com/charmbracelet/x/ansi"

	"karma/internal/model"
)

// Column geometry: two columns of gap between columns, a title floor, and the
// probe chain's floor (its natural width is driven by the longest fallback
// chain in the catalog, which would otherwise starve the title column). Rows
// live inside the group panel's body, so their available line is the panel's
// text width.
const (
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
func RenderListTable(w io.Writer, selected []*model.Check, term int) {
	if len(selected) == 0 {
		return
	}
	idW, titleW, chainW := listLayout(selected, term)
	groups := groupChecks(selected)
	for index, group := range groups {
		if index == 0 || groups[index-1].platform != group.platform {
			if index > 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w, headingBand(string(group.platform), term))
		}
		rows := make([]string, 0, len(group.checks))
		for _, check := range group.checks {
			rows = append(rows, listRow(check, idW, titleW, chainW))
		}
		head := []string{fillBand(" "+strings.ToUpper(string(group.aspect)), railInner(term), subBandStyle)}
		fmt.Fprintln(w, checkBlock(model.Info, head, rows, term))
	}
}

// listLayout splits the line between the three columns: the id keeps its natural
// width (it is the selector vocabulary), the title takes two fifths, and the
// chain gets the rest. A line too narrow for both drops the chain, which is
// metadata; nothing ever exceeds the line.
func listLayout(selected []*model.Check, term int) (idW, titleW, chainW int) {
	line := textWidth(term)
	idW, chainNat := listColumnWidths(selected)
	rest := line - (idW + listGap)
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

// probeChain is the chain as displayed: the fallback ladder of tier labels.
func probeChain(check *model.Check) string {
	labels := make([]string, 0, len(check.Probes))
	for _, probe := range check.Probes {
		labels = append(labels, probe.Label)
	}
	return strings.Join(labels, " → ")
}

// listRow is one catalog row: blue id, title in the default color, and the
// muted probe chain starting at a fixed column. The group panel's body box
// provides the indent, so the row starts at its id. Only the two sized cells
// carry a width (the id pads to its column, the title and chain wrap inside
// theirs); the panel trims each finished line, so padding after the last
// visible character never reaches the output.
func listRow(check *model.Check, idW, titleW, chainW int) string {
	id := lipgloss.NewStyle().Foreground(listIDColor).
		Padding(0, listGap, 0, 0).Width(idW + listGap).
		Render(check.ID)
	title := lipgloss.NewStyle().Width(titleW).Render(wordWrap(check.Title, titleW))
	if chainW == 0 {
		return lipgloss.JoinHorizontal(lipgloss.Top, id, title)
	}
	chain := lipgloss.NewStyle().Foreground(MutedColor).Width(chainW).
		Render(wordWrap(probeChain(check), chainW))
	return lipgloss.JoinHorizontal(lipgloss.Top, id, title,
		lipgloss.NewStyle().Width(listGap).Render(""), chain)
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
