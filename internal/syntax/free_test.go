// free(1)'s memory table: the columns its lowercase header names.

package syntax

import (
	"strings"
	"testing"

	"karma/internal/form"
)

// free's header is lowercase, so the columns come from the lexer's own header
// pattern, and the label column is one of them. The two rows print the same
// columns — "Swap:" carries three cells where "Mem:" carries six — so a cell
// keeps its color from one row to the next.
func TestFreeKeepsTheCellsColumns(t *testing.T) {
	styler := Painter("free")
	header := "               total        used        free      shared  buff/cache   available"
	if spans := styler(header); spans != nil {
		t.Fatalf("the header should only record anchors: %v", spans)
	}
	// free -h's own widths: the label in eight cells, every number in twelve.
	mem := "Mem:           1.9Gi       287Mi       134Mi       4.2Mi       1.5Gi       1.6Gi"
	swap := "Swap:              0B          0B          0B"
	for _, row := range []struct {
		line   string
		cells  []string
		column []int
	}{
		{mem, []string{"Mem:", "1.9Gi", "287Mi", "134Mi", "4.2Mi", "1.5Gi"}, []int{0, 1, 2, 3, 4, 0}},
		{swap, []string{"Swap:", "0B", "0B", "0B"}, []int{0, 1, 2, 3}},
	} {
		painted := form.PaintLine(row.line, styler(row.line))
		for index, cell := range row.cells {
			want := tableColumnStyles[row.column[index]].Style().Render(cell)
			if !strings.Contains(painted, want) {
				t.Errorf("%q: the cell %q should carry column %d's color: %q",
					row.line[:4], cell, row.column[index], plain(painted))
			}
		}
	}
}
