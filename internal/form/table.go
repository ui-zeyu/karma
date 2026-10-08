// Package form holds the shapes a check's body is drawn in: where a rule hit
// falls on the units a shape can paint, and how those units are laid out at the
// terminal's width.
//
// A form lays out records a collection read as fields, and the hits the reading
// layer stated on them (see model.Matcher); it decides no verdict of its own.
package form

import (
	"cmp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"

	"karma/internal/model"
)

// Table draws a body of records as a table: the column names across the top,
// one row per record, and the rule hits painted where they fell.
//
// Column widths come from the data — and from the panel, which the last column
// absorbs, because that is where the wide value lives (a command line, a path).
// Nothing is cut: a value too wide for its column wraps inside it, on as many
// lines as its column is narrow for, and each hit's reason is said under the
// column the hit fell in. Nothing here decides what the data means: the
// columns' alignment and color are the check's declaration, keyed by the
// column names its records carry, and the colors themselves are the palette's.
type Table struct {
	// Align is how each column sits in its width, by column name; a column the
	// map does not name is left-aligned. The name is the one the record set's
	// header carries, so a check whose tiers print different columns declares
	// one table and both read right.
	Align map[string]Alignment
	// Tint is the color of a column that wants a particular one, by index into
	// the tint cycle; other columns follow the cycle by position.
	Tint map[string]Tint
}

// Alignment is how one column's cells sit in their width.
type Alignment int8

const (
	// Left starts a cell at its column's left edge.
	Left Alignment = iota
	// Right ends it at the right edge, which is how a table of numbers reads.
	Right
)

// Tint is a column's color as an index into the tint cycle.
type Tint int8

// The gap between two columns, and the narrowest a column may be squeezed to
// before the row is left to wrap: a wrapped cell keeps its heading's first
// letters visible, and the whole table still ends inside the panel.
const (
	columnGap = 2
	minColumn = 4
)

// Render lays the block out: the head, then one row per item, with the
// caller's structural notes between them.
func (t Table) Render(block model.Block, opts model.RenderOptions) []string {
	columns := t.columnCount(block)
	if columns == 0 {
		return nil
	}
	widths := t.measure(block, columns, opts.Width)
	out := make([]string, 0, len(block.Items)+1)
	if len(block.Header) > 0 {
		out = append(out, t.headRow(block.Header, widths, opts)...)
	}
	for _, item := range block.Items {
		if item.Rec == nil {
			out = append(out, noteRow(item.Note, opts))
			continue
		}
		out = append(out, t.dataRow(item, block.Header, widths, opts)...)
	}
	return out
}

// columnCount is how many columns the block needs: the head's own count, and
// the widest record.
func (t Table) columnCount(block model.Block) int {
	columns := len(block.Header)
	for _, item := range block.Items {
		if item.Rec != nil {
			columns = max(columns, len(item.Rec.Fields))
		}
	}
	return columns
}

// measure sizes the columns: each as wide as its widest cell (the headings
// count), and the last one takes what is left of the panel. A panel too narrow
// for those widths takes them back from the widest column first, so the rows
// wrap in the columns that gave way.
func (t Table) measure(block model.Block, columns, width int) []int {
	widths := make([]int, columns)
	for index, name := range block.Header {
		widths[index] = max(widths[index], displayWidth(name))
	}
	for _, item := range block.Items {
		if item.Rec == nil {
			continue
		}
		for index, field := range item.Rec.Fields {
			widths[index] = max(widths[index], displayWidth(field.Value))
		}
	}
	width = max(width, minColumn)
	others := columnGap * (columns - 1)
	for _, column := range widths[:columns-1] {
		others += column
	}
	widths[columns-1] = max(width-others, minColumn)
	for total(widths) > width {
		// The non-last columns give way first — the wide value lives in the
		// last one, and every cell it loses is a line the row grows.
		widest := -1
		for index := range widths[:columns-1] {
			if widths[index] > minColumn && (widest < 0 || widths[index] > widths[widest]) {
				widest = index
			}
		}
		if widest < 0 {
			widest = columns - 1
			if widths[widest] <= minColumn {
				break
			}
		}
		widths[widest]--
	}
	return widths
}

// headRow is the column names over their columns, each taking its column's
// tint, so a column reads the same in the head as in the rows below it. A name
// wider than its column wraps like a value does.
func (t Table) headRow(header []string, widths []int, opts model.RenderOptions) []string {
	names := make([]string, len(widths))
	for index := range widths {
		if index < len(header) {
			names[index] = header[index]
		}
	}
	return t.rowLines(header, names, nil, widths, opts)
}

// dataRow is one record: its cells side by side in their columns, every value
// that does not fit wrapped inside its own column, and each hit's reason said
// under the column the hit fell in. The hits that belong to the record itself
// state their reason at the row's end.
func (t Table) dataRow(item model.BlockItem, header []string, widths []int, opts model.RenderOptions) []string {
	values := make([]string, len(widths))
	for index := range widths {
		if index < len(item.Rec.Fields) {
			values[index] = item.Rec.Fields[index].Value
		}
	}
	rows := t.rowLines(header, values, item.Matches, widths, opts)
	rows = append(rows, reasonLines(item.Matches, widths, opts)...)
	return withReasonRows(rows, recordReason(item.Matches), opts)
}

// rowLines lays one row of plain values in its columns: every value wrapped
// inside its own column, each line padded so the columns after it keep their
// places, and the row's hits painted on the lines that show their bytes. A
// value that fits its column is the one line it always was.
func (t Table) rowLines(header, values []string, matches []model.Match, widths []int, opts model.RenderOptions) []string {
	lastColumn := len(widths) - 1
	cells := make([][]string, len(widths))
	plains := make([][]string, len(widths))
	height := 1
	for index, width := range widths {
		segments := wrapCell(values[index], width)
		if len(segments) == 0 {
			segments = [][2]int{{0, 0}}
		}
		hits := cellHits(matches, index, len(values[index]))
		tint := t.tint(header, index, len(widths))
		for _, segment := range segments {
			plain := displayOf(values[index], segment)
			painted := paintValue(plain, segmentHits(hits, segment[0], segment[1]), tint, opts.Color)
			cells[index] = append(cells[index], painted)
			plains[index] = append(plains[index], plain)
		}
		height = max(height, len(cells[index]))
	}
	rows := make([]string, height)
	for line := range rows {
		parts := make([]string, len(widths))
		for index, width := range widths {
			text, plain := "", ""
			if line < len(cells[index]) {
				text, plain = cells[index][line], plains[index][line]
			}
			parts[index] = padCell(text, plain, width, index < lastColumn, t.align(header, index))
		}
		rows[line] = strings.TrimRight(strings.Join(parts, strings.Repeat(" ", columnGap)), " ")
	}
	return rows
}

// reasonLines is each column's reason, said under the column its hits fell in:
// the most severe message among them, with the count of the rest beside it. A
// hit with spans in two columns is said under the first — the account cell a
// conjunction begins with is the subject of its sentence.
func reasonLines(matches []model.Match, widths []int, opts model.RenderOptions) []string {
	columns := len(widths)
	groups := make([][]model.Match, columns)
	for _, match := range matches {
		if !match.Severity.IsSignal() || len(match.Spans) == 0 {
			continue
		}
		column := match.Spans[0].Field
		if column < 0 || column >= columns {
			continue
		}
		groups[column] = append(groups[column], match)
	}
	var rows []string
	for column, group := range groups {
		reason := ReasonFor(group)
		if reason == "" {
			continue
		}
		if opts.Color {
			reason = DimPaint().Render(reason)
		}
		indent := columnLeft(widths, column)
		if indent+displayWidth(reason) > opts.Width {
			// The reason does not fit under its column; it stands at the
			// table's left edge rather than being broken where the panel
			// runs out.
			indent = 0
		}
		rows = append(rows, strings.Repeat(" ", indent)+reason)
	}
	return rows
}

// recordReason is the reason of the hits that belong to the record itself —
// the ones no single field holds. It rides the row's last line.
func recordReason(matches []model.Match) string {
	var whole []model.Match
	for _, match := range matches {
		if match.Severity.IsSignal() && len(match.Spans) == 0 {
			whole = append(whole, match)
		}
	}
	return ReasonFor(whole)
}

// columnLeft is where a column begins on a row: the widths of the columns
// before it and the gaps between them.
func columnLeft(widths []int, index int) int {
	at := columnGap * index
	for _, width := range widths[:index] {
		at += width
	}
	return at
}

// wrapCell breaks value into lines of at most width display cells: at the last
// blank inside a line where there is one, hard at the width where there is not.
// Each line is a byte range of the value, so a hit's span keeps meaning on the
// line that shows its bytes.
func wrapCell(value string, width int) [][2]int {
	var lines [][2]int
	at := 0
	for at < len(value) {
		var (
			cells     int
			lastBlank = -1 // the byte just past the last blank inside this line
			end       = len(value)
			index     = at
			broke     bool
		)
		for index < len(value) {
			r, size := utf8.DecodeRuneInString(value[index:])
			w := displayWidth(string(r))
			if cells > 0 && cells+w > width {
				end = index
				broke = true
				break
			}
			cells += w
			if r == ' ' || r == '\t' {
				lastBlank = index + size
			}
			index += size
		}
		if broke && lastBlank > at {
			end = lastBlank
			index = lastBlank
		}
		lines = append(lines, [2]int{at, end})
		at = index
	}
	// A value ending in a blank leaves a line that holds only the blank.
	if len(lines) > 1 {
		last := lines[len(lines)-1]
		if strings.TrimSpace(value[last[0]:last[1]]) == "" {
			lines = lines[:len(lines)-1]
		}
	}
	return lines
}

// displayOf is the part of the value one wrapped line shows: the segment's
// bytes, with the blank a word break left at its end taken off — the break
// consumed it, and a blank paints nothing.
func displayOf(value string, segment [2]int) string {
	return strings.TrimRight(value[segment[0]:segment[1]], " ")
}

// segmentHits cuts one cell's hits to a wrapped segment of the value: the part
// of each span that falls inside the segment, in the segment's own
// coordinates.
func segmentHits(hits []paintHit, start, end int) []paintHit {
	var out []paintHit
	for _, hit := range hits {
		s, e := max(hit.start, start), min(hit.end, end)
		if e > s {
			out = append(out, paintHit{start: s - start, end: e - start, severity: hit.severity})
		}
	}
	return out
}

// withReasonRows ends a drawn row — one line or many — with the reason the
// reading layer states about it, ⟨…⟩ dimmed, beside the last line when it
// fits and on a line of its own when it does not. The forms that lay rows out
// share it.
func withReasonRows(rows []string, reason string, opts model.RenderOptions) []string {
	if len(rows) == 0 || reason == "" {
		return rows
	}
	painted := reason
	if opts.Color {
		painted = DimPaint().Render(reason)
	}
	last := rows[len(rows)-1]
	if displayWidth(last)+2+displayWidth(reason) <= opts.Width {
		rows[len(rows)-1] = last + "  " + painted
		return rows
	}
	return append(rows, painted)
}

// paintHit is one span of severity to lay over a value: where it starts and
// ends in the text being painted.
type paintHit struct {
	start, end int
	severity   model.Severity
}

// cellHits is the hits that paint one cell: each span a rule stated on this
// field, and the whole cell for a hit that belongs to the record itself. A
// span outside the value paints nothing here; the cell it does fall in paints
// it.
func cellHits(matches []model.Match, index, length int) []paintHit {
	var hits []paintHit
	for _, hit := range matches {
		if !hit.Severity.IsSignal() {
			continue
		}
		if len(hit.Spans) == 0 {
			hits = append(hits, paintHit{start: 0, end: length, severity: hit.Severity})
			continue
		}
		for _, span := range hit.Spans {
			if span.Field != index {
				continue
			}
			start, end := clamp(span.Start, 0, length), clamp(span.End, 0, length)
			if end > start {
				hits = append(hits, paintHit{start: start, end: end, severity: hit.Severity})
			}
		}
	}
	return hits
}

// tint is the paint of one column: the color its name declares, the cycle's
// own order by position otherwise. The last column stays plain unless it asks
// for a tint — that is where the wide value runs to the panel's edge, and a
// color there would compete with the hits inside it.
func (t Table) tint(header []string, index, columns int) Paint {
	if name := headerName(header, index); name != "" {
		if tint, ok := t.Tint[name]; ok {
			return ColumnPaint(int(tint))
		}
	}
	if index == columns-1 {
		return Paint{}
	}
	return ColumnPaint(index)
}

// align is how one column sits in its width: the alignment its name declares,
// left otherwise.
func (t Table) align(header []string, index int) Alignment {
	if alignment, ok := t.Align[headerName(header, index)]; ok {
		return alignment
	}
	return Left
}

// headerName is the name of one column; a column the header does not reach has
// none (a record wider than the head it travels with).
func headerName(header []string, index int) string {
	if index < len(header) {
		return header[index]
	}
	return ""
}

// paintValue paints one cell's value with the base tint under its hits, the
// most severe painting last so that it wins where two cover the same bytes. A
// span past the cut end of a truncated value paints nothing.
func paintValue(value string, hits []paintHit, base Paint, color bool) string {
	if !color {
		return value
	}
	if len(hits) == 0 {
		return base.Render(value)
	}
	ordered := slices.Clone(hits)
	slices.SortStableFunc(ordered, func(a, b paintHit) int {
		return cmp.Compare(b.severity, a.severity)
	})
	winner := make([]int, len(value))
	for index, hit := range ordered {
		for at := max(hit.start, 0); at < min(hit.end, len(value)); at++ {
			winner[at] = index + 1
		}
	}
	var out strings.Builder
	start, current := 0, 0
	for at := 0; at <= len(value); at++ {
		next := 0
		if at < len(value) {
			next = winner[at]
		}
		if at == len(value) || next != current {
			if at > start {
				paint := base
				if current > 0 {
					paint = SeverityPaint(ordered[current-1].severity)
				}
				out.WriteString(paint.Render(value[start:at]))
			}
			start, current = at, next
		}
	}
	return out.String()
}

// padCell pads a painted cell out to its column: the last column of a row is
// left as it stands, so nothing follows the row's own text.
func padCell(painted, plain string, width int, pad bool, align Alignment) string {
	if !pad {
		return painted
	}
	slack := max(width-displayWidth(plain), 0)
	if slack == 0 {
		return painted
	}
	if align == Right {
		return strings.Repeat(" ", slack) + painted
	}
	return painted + strings.Repeat(" ", slack)
}

// noteRow is a structural row the caller inserted (a counted gap where the
// display budget hid records).
func noteRow(note string, opts model.RenderOptions) string {
	if !opts.Color {
		return note
	}
	return Paint{Faint: true, Italic: true}.Render(note)
}

// total is what a row of these columns occupies, gaps included.
func total(widths []int) int {
	sum := columnGap * (len(widths) - 1)
	for _, width := range widths {
		sum += width
	}
	return sum
}

func displayWidth(text string) int { return lipgloss.Width(text) }

func clamp(value, low, high int) int { return min(max(value, low), high) }
