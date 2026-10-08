// A probe: one tier of a check's walk, and the step its probes answer as a
// whole.

package model

// Probe is one tier: what to run, how its output becomes the body, and how much
// of that body the tier wants. Assemble is the tier's own join, run on the raw
// output before any `== ` split (nil uses the output as it stands); Adapt only
// turns this tier's output into the same shape as the other tiers and runs
// within the section; normalization that must run whichever tier wins hangs on
// Check.Normalize.
//
// Whether the tier can run at all is its own answer at run time — a Native body
// reports ErrTierUnavailable, a missing binary exits 127 — never a declaration
// read before the walk: one mechanism, so a tier cannot be declared present on a
// host that lacks it, or declared missing by a probe that misread.
type Probe struct {
	Label string
	// Title is the section title the probe's body carries in the report. The
	// empty title is the untitled leading section, which is what a tier with one
	// output has; a step that answers with several sections names each one here,
	// so the reading never has to recognize a boundary in the bytes it read.
	Title string
	// Titles names the sections one answer carries, for a tier that prints
	// several parts of one computation in one output. Each is a line of the body
	// as that tier prints it, and the reading opens a section titled with it at
	// every occurrence — the tier prints a title only in front of rows it has, so
	// a part with nothing to show states nothing. Empty means the answer is the
	// one section Title names.
	Titles []string
	// Inv is what the tier runs: one of the invocation kinds, a file-list walk
	// included.
	Inv Invocation
	// Assemble is the tier's own join: the body emits a marked record stream
	// (records the join can also explain, not only render), and this one
	// function reduces it to rows.
	Assemble Transformer
	Adapt    Normalizer
	Cap      RowCap
}

// Runs reports whether a run in this source walks the probe: the invocation
// answers for itself, whatever kind it is.
func (p Probe) Runs(source Source) bool {
	return p.Inv.RunsOn(source)
}

// Step is one step of a check's walk: the probes that answer as a whole. One
// probe is the common step. Several are the source that needs one process per
// item — a PS-less Windows target runs one reg.exe per key because the local
// channel has no shell to loop in — where the step answers when any member
// answered and the bodies join in declaration order. Declaring them as
// alternatives to one another would let the walk stop at the first key that
// exists and silently drop the rest of the evidence.
type Step []Probe
