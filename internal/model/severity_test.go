// The severity vocabulary is one table: the level names, the name lookup the
// selectors and flags use, and the floor arithmetic all read it, so a level
// cannot be named twice and drift.

package model

import "testing"

func TestSeverityNamesCoverTheLevels(t *testing.T) {
	if len(severityNames) != int(Benign)+1 {
		t.Fatalf("severityNames has %d entries, want one per level (Benign is %d)",
			len(severityNames), Benign)
	}
	for level := Critical; level <= Benign; level++ {
		name := level.String()
		if name == "unknown" {
			t.Fatalf("level %d has no name", level)
		}
		back, ok := SeverityByName(name)
		if !ok || back != level {
			t.Errorf("%q resolves to %v (ok=%v), want %v", name, back, ok, level)
		}
	}
	if got := Severity(-1).String(); got != "unknown" {
		t.Errorf("a level below critical is %q, want unknown", got)
	}
	if got := Severity(Benign + 1).String(); got != "unknown" {
		t.Errorf("a level above benign is %q, want unknown", got)
	}
	if _, ok := SeverityByName("severe"); ok {
		t.Error("an unknown name must not resolve")
	}
}

func TestSeverityFloorKeepsAtAndAboveItsLevel(t *testing.T) {
	for _, level := range []Severity{Critical, High, Medium, Low, Info, Benign} {
		floor := FloorAbove(level)
		if !floor.Keeps(level) {
			t.Errorf("%v should keep its own level %v", floor, level)
		}
		for _, more := range []Severity{Critical, High, Medium, Low, Info, Benign} {
			want := more <= level
			if got := floor.Keeps(more); got != want {
				t.Errorf("%v.Keeps(%v) = %v, want %v", floor, more, got, want)
			}
		}
		if got := floor.String(); got != level.String() {
			t.Errorf("floor above %v names itself %q", level, got)
		}
	}
	if !FloorAll.Keeps(Benign) || !FloorAll.Keeps(Critical) {
		t.Error("the zero floor must keep every row")
	}
	if got := FloorAll.String(); got != "all" {
		t.Errorf("the zero floor is %q, want all", got)
	}
	if !FloorAbove(Benign).Keeps(Benign) {
		t.Error("the quietest floor keeps every row too")
	}
}

func TestParseSeverityFloor(t *testing.T) {
	if floor, ok := ParseSeverityFloor("all"); !ok || floor != FloorAll {
		t.Errorf("all should be the whole report, got %v (ok=%v)", floor, ok)
	}
	floor, ok := ParseSeverityFloor("high")
	if !ok || floor != FloorAbove(High) {
		t.Errorf("high resolved to %v (ok=%v)", floor, ok)
	}
	if _, ok := ParseSeverityFloor("HIGH"); ok {
		t.Error("the vocabulary is lowercase")
	}
	if _, ok := ParseSeverityFloor(""); ok {
		t.Error("an empty word must not resolve")
	}
}
