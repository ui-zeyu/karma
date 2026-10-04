package render

import "testing"

func TestSplitWide(t *testing.T) {
	cases := []struct {
		rest             int
		titleNat, chaNat int
		wantTitle        int
		wantChain        int
	}{
		// Normal: split proportionally to natural width, the sum always rest
		{104, 40, 70, 37, 67},
		{52, 40, 70, 18, 34},
		// Filled out: the wide columns exceed their natural width and the slack
		// stays inside the cells
		{200, 28, 66, 59, 141},
		// Very narrow terminal: floor widths, the rest left to the terminal's
		// soft wrap
		{20, 40, 70, 14, 16},
	}
	for _, c := range cases {
		title, chain := splitWide(c.rest, c.titleNat, c.chaNat)
		if title != c.wantTitle || chain != c.wantChain {
			t.Errorf("splitWide(%d, %d, %d) = (%d, %d), want (%d, %d)",
				c.rest, c.titleNat, c.chaNat, title, chain, c.wantTitle, c.wantChain)
		}
		if title+chain != c.wantTitle+c.wantChain {
			t.Errorf("splitWide(%d, %d, %d) column sum %d does not match the expectation", c.rest, c.titleNat, c.chaNat, title+chain)
		}
	}
}
