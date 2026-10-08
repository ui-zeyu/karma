// Painting one line by span: the palette (palette.go) states the colors, and
// this file states where they land.

package form

import (
	"slices"
	"strings"
)

// Span is one stretch of a line to paint: its byte range and the paint it
// takes. A line's spans come from the rules that judged it (a hit) or from a
// syntax lexer's coloring, and whoever draws the line paints them together.
type Span struct {
	Start int
	End   int
	Style Paint
}

// PaintLine paints one line by span: spans apply in stacking order, later ones
// covering earlier ones (the syntax layer lands first, hit spans and comment
// muting later). Non-overlapping spans leave the output unchanged, and an empty
// span set returns the text as is.
//
// The line is cut at every span boundary; each cut segment takes the last span
// covering it whole, and neighbouring segments with the same winner merge back
// into one run. Every maximal run of bytes painted by the same span is bounded
// by span boundaries, so the result matches the per-byte rule without touching
// each byte.
func PaintLine(text string, spans []Span) string {
	if len(spans) == 0 {
		return text
	}
	cuts := make([]int, 0, 2+2*len(spans))
	cuts = append(cuts, 0, len(text))
	for _, span := range spans {
		start, end := max(span.Start, 0), min(span.End, len(text))
		if end > start { // a malformed span paints nothing, as before
			cuts = append(cuts, start, end)
		}
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	var out strings.Builder
	runStart, winner := 0, -1
	for index := 1; index < len(cuts); index++ {
		start, end := cuts[index-1], cuts[index]
		next := -1
		for probe, span := range spans { // later spans paint over earlier ones
			if span.Start <= start && end <= span.End {
				next = probe
			}
		}
		if next == winner {
			continue
		}
		if winner >= 0 {
			out.WriteString(spans[winner].Style.Render(text[runStart:start]))
		} else {
			out.WriteString(text[runStart:start])
		}
		winner, runStart = next, start
	}
	if winner >= 0 {
		return out.String() + spans[winner].Style.Render(text[runStart:])
	}
	return out.String() + text[runStart:]
}
