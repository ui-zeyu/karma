// The outcome vocabulary is one table: the result stream writes a name from it,
// so an outcome cannot be spelled twice.

package model

import (
	"slices"
	"testing"
)

func TestOutcomeNamesCoverTheOutcomes(t *testing.T) {
	if len(outcomeNames) != int(Failed)+1 {
		t.Fatalf("outcomeNames has %d entries, want one per outcome (Failed is %d)",
			len(outcomeNames), Failed)
	}
	for outcome := Collected; outcome <= Failed; outcome++ {
		name := outcome.String()
		if name == "unknown" {
			t.Fatalf("outcome %d has no name", outcome)
		}
		back, ok := ParseOutcome(name)
		if !ok || back != outcome {
			t.Errorf("%q resolves to %v (ok=%v), want %v", name, back, ok, outcome)
		}
	}
	if got := Outcome(-1).String(); got != "unknown" {
		t.Errorf("an outcome below collected is %q, want unknown", got)
	}
	if got := Outcome(Failed + 1).String(); got != "unknown" {
		t.Errorf("an outcome above failed is %q, want unknown", got)
	}
	if _, ok := ParseOutcome("collected "); ok {
		t.Error("an unknown name must not resolve")
	}
	if got := OutcomeNames(); !slices.Equal(got, []string{"collected", "skipped", "failed"}) {
		t.Errorf("the protocol's vocabulary is %v", got)
	}
}
