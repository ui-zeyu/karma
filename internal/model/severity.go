// Severity: how a row is graded, and how much of the report a run keeps.

package model

import "slices"

// Severity is the severity of a hit line. Declaration order is severity order:
// smaller is more severe. "Is this a signal line" is exactly s < Info.
type Severity int

const (
	Critical Severity = iota
	High
	Medium
	Low
	Info
	Benign
)

// severityNames is the name of each severity, in the Severity declaration
// order; the name lookup and the flag vocabularies read it, so a level is named
// once. A test pins its length against the last constant.
var severityNames = []string{"critical", "high", "medium", "low", "info", "benign"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// SeverityByName resolves a severity name; ok is false for an unknown name.
func SeverityByName(name string) (Severity, bool) {
	if index := slices.Index(severityNames, name); index >= 0 {
		return Severity(index), true
	}
	return 0, false
}

// SeverityNames returns every severity name in declaration order; the selector
// and flag vocabularies and their messages read it.
func SeverityNames() []string { return slices.Clone(severityNames) }

// IsSignal reports whether a line is a finding: it lights up the hit and the
// rail, is always printed, and is exempt from the display budget. benign
// (baseline rows of routine listings) and Info (no hit) are quiet levels.
func (s Severity) IsSignal() bool { return s < Info }

// SeverityFloor is how much of a report a run keeps: a row below the floor is
// counted like a filtered line and left out of the document. The value is one
// past the least severe level it keeps, which is what makes the zero value mean
// "no floor" — an unset run option has to show the whole report — while a level
// still names itself through FloorAbove.
type SeverityFloor Severity

// FloorAll keeps every row, the quiet baseline levels included. It is the zero
// value, and the run option's default.
const FloorAll SeverityFloor = 0

// FloorAbove is the floor that keeps level and every more severe level.
func FloorAbove(level Severity) SeverityFloor { return SeverityFloor(level) + 1 }

// Keeps reports whether a row at this severity is at or above the floor.
func (f SeverityFloor) Keeps(severity Severity) bool {
	return f == FloorAll || severity < Severity(f)
}

// String names the least severe level the floor keeps, or "all" for the floor
// that keeps every row.
func (f SeverityFloor) String() string {
	if f == FloorAll {
		return "all"
	}
	return Severity(f - 1).String()
}

// ParseSeverityFloor resolves a --min-severity word: "all" keeps the whole
// report, and a level name keeps that level and every more severe one.
func ParseSeverityFloor(name string) (SeverityFloor, bool) {
	if name == "all" {
		return FloorAll, true
	}
	level, ok := SeverityByName(name)
	if !ok {
		return FloorAll, false
	}
	return FloorAbove(level), true
}
