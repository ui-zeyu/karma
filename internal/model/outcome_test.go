// The outcome vocabulary is one table: the result stream writes a name from it,
// so an outcome cannot be spelled twice.

package model

import "testing"

func TestOutcomeNamesCoverTheOutcomes(t *testing.T) {
	if len(outcomeNames) != int(Failed)+1 {
		t.Fatalf("outcomeNames has %d entries, want one per outcome (Failed is %d)",
			len(outcomeNames), Failed)
	}
	for outcome := Collected; outcome <= Failed; outcome++ {
		if name := outcome.String(); name == "unknown" {
			t.Fatalf("outcome %d has no name", outcome)
		}
	}
	if got := Outcome(-1).String(); got != "unknown" {
		t.Errorf("an outcome below collected is %q, want unknown", got)
	}
	if got := Outcome(Failed + 1).String(); got != "unknown" {
		t.Errorf("an outcome above failed is %q, want unknown", got)
	}
}
