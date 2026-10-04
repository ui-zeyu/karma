// The `karma list` table: platform, aspect, id, title, probe chain, with column
// colors sharing the severity palette. The table fills the terminal width:
// platform/aspect/id size to their content, and the remaining width is split
// proportionally to natural width between the title and probe-chain columns,
// with over-long content wrapping inside its cell (a six-tier fallback chain
// used to push the whole table past the terminal width).
package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"

	"karma/internal/model"
)

type listRow struct {
	platform, aspect, id, title, chain string
}

// RenderListTable draws the check catalog table (both platforms merged, told
// apart by the platform column). The width comes from the caller (terminal
// width or a fallback).
func RenderListTable(w io.Writer, selected []*model.Check, width int) {
	rows := make([]listRow, 0, len(selected))
	for _, check := range selected {
		var chain []string
		for _, probe := range check.Probes {
			chain = append(chain, probe.Label)
		}
		rows = append(rows, listRow{
			platform: string(check.Platform),
			aspect:   string(check.Aspect),
			id:       check.ID,
			title:    check.Title,
			chain:    strings.Join(chain, " → "),
		})
	}

	// Natural width of each column (widest of header and content)
	platW, aspectW, idW := lipgloss.Width("platform"), lipgloss.Width("aspect"), lipgloss.Width("id")
	titleNat, chainNat := lipgloss.Width("title"), lipgloss.Width("probe chain")
	for _, row := range rows {
		platW = max(platW, lipgloss.Width(row.platform))
		aspectW = max(aspectW, lipgloss.Width(row.aspect))
		idW = max(idW, lipgloss.Width(row.id))
		titleNat = max(titleNat, lipgloss.Width(row.title))
		chainNat = max(chainNat, lipgloss.Width(row.chain))
	}
	// 5 columns inside 6 borders; the remaining width goes to the two wide
	// columns
	titleW, chainW := splitWide(width-platW-aspectW-idW-6, titleNat, chainNat)

	bordered := lipgloss.NewStyle().Foreground(MutedColor)
	platformSt := lipgloss.NewStyle().Foreground(MutedColor)
	aspectSt := lipgloss.NewStyle().Bold(true)
	idSt := lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	chainSt := lipgloss.NewStyle().Foreground(MutedColor)

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(bordered).
		StyleFunc(func(row, col int) lipgloss.Style {
			st := lipgloss.NewStyle()
			switch col {
			case 0:
				st = platformSt
			case 1:
				st = aspectSt
			case 2:
				st = idSt
			case 4:
				st = chainSt
			}
			if row == table.HeaderRow {
				return st.Bold(true)
			}
			switch col {
			case 3:
				return st.Width(titleW)
			case 4:
				return st.Width(chainW)
			}
			return st
		}).
		Headers("platform", "aspect", "id", "title", "probe chain")
	for _, row := range rows {
		t.Row(row.platform, row.aspect, row.id, row.title, row.chain)
	}
	fmt.Fprintln(w, t.Render())
}

// splitWide splits the remaining width between the title and probe-chain
// columns: proportionally to natural width, so the table fills the terminal;
// on a very narrow terminal both fall back to floor widths (anything narrower
// is left to the terminal's soft wrap). The two values always sum to rest
// (except when the floors apply).
func splitWide(rest, titleNat, chainNat int) (int, int) {
	const titleFloor, chainFloor = 14, 16
	if rest < titleFloor+chainFloor {
		return titleFloor, chainFloor
	}
	title := titleNat * rest / (titleNat + chainNat)
	return max(title, titleFloor), rest - max(title, titleFloor)
}
