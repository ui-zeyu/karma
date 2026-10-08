// A check: its walk, its title-syntax overrides, and the result of one run of
// it.

package model

import "time"

// Check is one check: its fallback walk, its already-composed filters and
// rules, and an optional body normalizer.
type Check struct {
	ID       string
	Title    string
	Aspect   Aspect
	Platform Platform // catalog platform: the list group banner and the platform selector
	Steps    []Step   // the walk: one step per tier or group of tiers that answer together
	Filters  []LineFilter
	Rules    []Matcher
	// Timeout is this check's own budget, overriding the run option; 0 means the
	// run's. It bounds the whole walk (runner.runCheck), not one tier's call.
	Timeout   time.Duration
	Syntax    Syntax     // syntax declaration for the presentation layer; empty for none
	Normalize Normalizer // normalizes the winning body per section; the section title is passed and only dialect alignment (Probe.Adapt) reads it
	// Form is the shape this check's body is drawn in (a table, a column of
	// ls -l rows, ...). It is also the tail of the reading: the form projects
	// the rule hits onto the units it can paint. Nil draws the body as text.
	Form      Form
	ScanBytes int // 0 means the default read cap, reader.MaxScanBytes
	// SectionSyntax overrides Syntax per section: the first entry whose Title
	// glob (path.Match) matches the section title wins, other sections keep
	// Syntax. A section usually carries one source's shape, so mixed-output
	// checks (a listing followed by the files' contents) declare one override
	// per shape instead of one combined lexer.
	SectionSyntax []SectionSyntax
}

// SectionSyntax is one title-syntax override of Check.Syntax.
type SectionSyntax struct {
	Title  string // glob against the section title (path.Match)
	Syntax Syntax
}

// StepsFor is one source's walk of the check: the probes that source runs, in
// declaration order, with the steps it emptied dropped. A check can hold both
// sources' tiers side by side; the walk never mixes them.
func (c *Check) StepsFor(source Source) []Step {
	steps := make([]Step, 0, len(c.Steps))
	for _, step := range c.Steps {
		members := make(Step, 0, len(step))
		for _, probe := range step {
			if probe.Runs(source) {
				members = append(members, probe)
			}
		}
		if len(members) > 0 {
			steps = append(steps, members)
		}
	}
	return steps
}

// TierLabels names every tier the check declares, in walk order — what a run
// that walked none of them says it skipped.
func (c *Check) TierLabels() []string {
	var labels []string
	for _, step := range c.Steps {
		for _, probe := range step {
			labels = append(labels, probe.Label)
		}
	}
	return labels
}

// CheckResult is the outcome of one check. Outcome and Note together say what
// happened to the walk; document decides visibility on its own, so the
// presentation layer reads the outcome only to tell a skipped check from a
// collected one. Raw is the channel's stdout exactly as collected, before the
// reading layer caps or shapes anything.
// Document is the reading result, computed once when the report is built, and
// the presentation layer only reads it.
type CheckResult struct {
	Check         *Check
	ProbeLabel    string
	Outcome       Outcome
	SkippedLabels []string
	// Raw is the tier's own text, exactly as collected. A tier that read fields
	// instead states them in Records, and Raw is the readable rendering of them
	// (what a fallback panel prints, and what the evidence is).
	Raw      string
	Records  *RecordSet
	Stderr   string
	Note     string
	Document Document
}
