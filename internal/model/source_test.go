// The run's source: which side of the wire reads the evidence, and which of a
// check's tiers that side walks.

package model

import (
	"context"
	"slices"
	"testing"
)

func TestChannelNamesItsSource(t *testing.T) {
	// A channel reads with one source, and it is the channel that says which:
	// karma's own bodies run only where karma itself runs.
	for channel, want := range map[Channel]Source{
		ChanLocal: SourceNative,
		ChanSSH:   SourceSh,
		ChanTTYD:  SourceSh,
	} {
		if got := channel.Source(); got != want {
			t.Errorf("%v.Source() = %q, want %q", channel, got, want)
		}
	}
}

func TestSourceRuns(t *testing.T) {
	// The kind states the side: in-process bodies exist where karma runs, a
	// Script tier is the sh source's, and a command runs wherever the session
	// points.
	fields := Fields{Read: func(context.Context) (*RecordSet, error) { return nil, nil }}
	native := Native{Body: func(context.Context) (string, error) { return "", nil }}
	script := Script{Run: "ps -ef", Parse: func(string) (*RecordSet, error) { return nil, nil }}
	command := NewCommand("ps", "-ef")
	for _, c := range []struct {
		source Source
		inv    Invocation
		want   bool
	}{
		{SourceNative, fields, true}, {SourceSh, fields, false},
		{SourceNative, native, true}, {SourceSh, native, false},
		{SourceNative, script, false}, {SourceSh, script, true},
		{SourceNative, command, true}, {SourceSh, command, true},
	} {
		if got := c.source.Runs(c.inv); got != c.want {
			t.Errorf("%q.Runs(%T) = %v, want %v", c.source, c.inv, got, c.want)
		}
	}
}

func TestStepsForKeepsOneSide(t *testing.T) {
	check := &Check{ID: "both", Steps: []Step{
		{{Label: "native", Inv: Fields{Read: func(context.Context) (*RecordSet, error) { return nil, nil }}}},
		{{Label: "sh", Inv: Script{Run: "ps -ef", Parse: func(string) (*RecordSet, error) { return nil, nil }}}},
		{{Label: "both", Inv: NewCommand("ps", "-ef")}},
	}}
	nativeSteps := check.StepsFor(SourceNative)
	if len(nativeSteps) != 2 {
		t.Fatalf("the native walk = %d steps, want the in-process and the command tiers", len(nativeSteps))
	}
	if nativeSteps[0][0].Label != "native" || nativeSteps[1][0].Label != "both" {
		t.Fatalf("the native walk = %v", nativeSteps)
	}
	shSteps := check.StepsFor(SourceSh)
	if len(shSteps) != 2 || shSteps[0][0].Label != "sh" || shSteps[1][0].Label != "both" {
		t.Fatalf("the sh walk = %v", shSteps)
	}
	if labels := check.TierLabels(); !slices.Equal(labels, []string{"native", "sh", "both"}) {
		t.Fatalf("labels = %v", labels)
	}

	// A step whose every probe belongs to the other side drops whole, and a
	// check left with no step of this source has an empty walk.
	nativeOnly := &Check{ID: "n", Steps: check.Steps[:1]}
	if steps := nativeOnly.StepsFor(SourceSh); len(steps) != 0 {
		t.Fatalf("a native-only check has no sh walk: %v", steps)
	}
}
