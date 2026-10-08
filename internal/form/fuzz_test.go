// The span stacker against arbitrary input: spans are built from text a target
// printed, and a malformed one must paint nothing rather than panic.

package form

import (
	"math/rand"
	"testing"

	"karma/internal/model"
)

// fuzzStyles is the palette's paints, plus the zero paint (no attributes at all).
var fuzzStyles = []Paint{
	SeverityPaint(model.Critical), SeverityPaint(model.High),
	SeverityPaint(model.Medium), SeverityPaint(model.Low),
	MutedPaint(), AccentPaint(), DimPaint(), {},
}

func FuzzPaintLine(f *testing.F) {
	f.Add("root:x:0:0 (deleted)", int64(0), uint8(0))
	f.Add("", int64(7), uint8(3))
	f.Add("plain", int64(-5), uint8(2))
	f.Fuzz(func(t *testing.T, text string, seed int64, count uint8) {
		rng := rand.New(rand.NewSource(seed))
		spans := make([]Span, int(count)%6)
		for i := range spans {
			// end may precede start: malformed spans must be ignored, not panic
			start := rng.Intn(len(text) + 1)
			end := rng.Intn(len(text)+2) - 1
			spans[i] = Span{Start: start, End: end, Style: fuzzStyles[rng.Intn(len(fuzzStyles))]}
		}
		if len(spans) == 0 {
			if got := PaintLine(text, spans); got != text {
				t.Fatalf("no spans must return the text as is: got %q", got)
			}
			return
		}
		wellFormed := false
		for _, span := range spans {
			if span.End > span.Start {
				wellFormed = true
			}
		}
		got := PaintLine(text, spans)
		if !wellFormed && got != text {
			t.Fatalf("malformed spans paint nothing: got %q for %q", got, text)
		}
	})
}
