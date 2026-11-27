// The audit run: collect one snapshot, judge it, and render the findings.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/spf13/cobra"

	"karma/internal/audit"
)

// runAudit is the default action of the command and of `karma audit`.
func runAudit(ctx context.Context, cmd *cobra.Command, w io.Writer, words []string, flags auditFlags) error {
	parsed, err := parseScope(words)
	if err != nil {
		return usagef(cmd, "%s", err)
	}
	if flags.json && flags.evidence {
		return usagef(cmd, "--evidence prints the text inventories after a text report; the machine-readable inventories are \"karma show <section> --json\"")
	}
	plan := parsed.plan()
	snapshot, collectErr := collect(ctx, cmd, flags, plan, flags.json)
	if snapshot == nil {
		return collectErr
	}
	report := audit.Judge(snapshot, plan.Filter)
	options := renderOptions(w, flags, plan.Filter)
	return present(w, flags, pageFuncs{
		write: func(w io.Writer) error { return audit.WriteJSON(w, report) },
		draw:  func(w io.Writer, options audit.RenderOptions) { audit.Render(w, report, options) },
	}, options, collectErr)
}

// page is the text/JSON pair one result presents as: the audit's report, one
// show section or one graph view. The commands share one present step, so
// the dispatch and the collectErr return are stated once.
type page interface {
	WriteJSON(io.Writer) error
	Render(w io.Writer, options audit.RenderOptions)
}

// pageFuncs adapts the audit package's free functions to the pair.
type pageFuncs struct {
	write func(io.Writer) error
	draw  func(w io.Writer, options audit.RenderOptions)
}

func (p pageFuncs) WriteJSON(w io.Writer) error                     { return p.write(w) }
func (p pageFuncs) Render(w io.Writer, options audit.RenderOptions) { p.draw(w, options) }

// present writes the machine answer or draws the page, and hands the
// collection error back either way: a report that rendered is still a run
// the interrupt cut short.
func present(w io.Writer, flags auditFlags, view page, options audit.RenderOptions, collectErr error) error {
	if flags.json {
		if err := view.WriteJSON(w); err != nil {
			return err
		}
		return collectErr
	}
	view.Render(w, options)
	return collectErr
}

// runShow prints one collected inventory without judging it. The section
// decides what the collection reads; the scope's units, pids and paths
// narrow the rows to the relations they name.
func runShow(ctx context.Context, cmd *cobra.Command, w io.Writer, words []string, flags auditFlags) error {
	section, ok := audit.SectionFor(words[0])
	if !ok {
		return usagef(cmd, "unknown show target %q (%s)", words[0], strings.Join(audit.ShowWords(), ", "))
	}
	parsed, err := parseScope(words[1:])
	if err != nil {
		return usagef(cmd, "%s", err)
	}
	plan := section.Plan(parsed.plan())
	snapshot, collectErr := collect(ctx, cmd, flags, plan, flags.json)
	if snapshot == nil {
		return collectErr
	}
	options := renderOptions(w, flags, plan.Filter)
	view := audit.NewView(snapshot, options.Filter)
	return present(w, flags, pageFuncs{
		write: func(w io.Writer) error { return audit.WriteShowJSON(w, view, section, words[0], options) },
		draw:  func(w io.Writer, options audit.RenderOptions) { audit.RenderShow(w, view, section, words[0], options) },
	}, options, collectErr)
}

// runObjectGraph prints one object's relation graph and the findings that
// touch it. The seed is parsed before the collection, so a mistyped selector
// fails in milliseconds rather than after the budget.
func runObjectGraph(ctx context.Context, cmd *cobra.Command, w io.Writer, word string, flags auditFlags) error {
	seed, err := audit.ParseGraphSeed(word)
	if err != nil {
		return usagef(cmd, "%s", err)
	}
	plan := audit.ObjectGraphPlan(seed)
	snapshot, collectErr := collect(ctx, cmd, flags, plan, flags.json)
	if snapshot == nil {
		return collectErr
	}
	view, err := audit.BuildObjectGraph(ctx, snapshot, seed)
	if err != nil {
		return usagef(cmd, "%s", err)
	}
	options := renderOptions(w, flags, plan.Filter)
	return present(w, flags, pageFuncs{
		write: func(w io.Writer) error { return audit.WriteGraphJSON(w, view) },
		draw:  func(w io.Writer, options audit.RenderOptions) { audit.RenderGraph(w, view, options) },
	}, options, collectErr)
}

// collect is the tail every collecting command shares: one snapshot under the
// run's time budget, then the --since boundary applied to it. The JSON and
// text branches stay at the call sites.
func collect(ctx context.Context, cmd *cobra.Command, flags auditFlags, plan audit.Plan, quiet bool) (*audit.Snapshot, error) {
	snapshot, err := collectSnapshot(ctx, plan, flags.timeout, quiet)
	if snapshot == nil {
		return nil, err
	}
	if err := applySince(snapshot, flags.since); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// collectSnapshot reads this host in process under the run's time budget. A
// stopped collection still returns the snapshot it read, so the operator sees
// the partial answer and the exit status states why it stopped. The progress
// band lives here, not at the call sites: every collecting command gets the
// same line, the same interrupt state and the same quiet JSON behavior by
// construction. quiet suppresses the band for machine output.
func collectSnapshot(ctx context.Context, plan audit.Plan, budget time.Duration, quiet bool) (*audit.Snapshot, error) {
	p := newProgress(quiet)
	p.watch(ctx)
	defer p.done()
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	snapshot, err := audit.CollectLocal(ctx, plan, stageProgress(p))
	if err == nil {
		return snapshot, nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return snapshot, failf(ExitInterrupted, "collection interrupted: %v", err)
	case errors.Is(err, context.DeadlineExceeded):
		return snapshot, failf(ExitEnvironment, "collection timed out: %v", err)
	default:
		return snapshot, failf(ExitInternal, "collection: %v", err)
	}
}

// auditFlags are the run options the audit and show modes share.
type auditFlags struct {
	json     bool
	evidence bool
	since    sinceSpec
	timeout  time.Duration
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func terminalWidth(w io.Writer) int {
	file, ok := w.(*os.File)
	if !ok {
		return 100
	}
	if size, _, err := term.GetSize(int(file.Fd())); err == nil && size > 0 {
		return size
	}
	return 100
}

// sinceKind is the one --since boundary grammar: the collected provision
// edge, the host's boot, or an operator instant.
type sinceKind uint8

const (
	sinceProvision sinceKind = iota
	sinceBoot
	sinceOperator
)

// sinceSpec is one parsed --since value: the boundary kind and, for an
// operator input, the instant it names.
type sinceSpec struct {
	kind sinceKind
	at   time.Time
}

// parseSince reads a --since value once, at option parse time, so a mistyped
// boundary fails before the collection starts and a duration anchors at that
// moment's clock reading.
func parseSince(value string) (sinceSpec, error) {
	switch value {
	case "", "provision":
		return sinceSpec{kind: sinceProvision}, nil
	case "boot":
		return sinceSpec{kind: sinceBoot}, nil
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return sinceSpec{kind: sinceOperator, at: time.Now().Add(-duration)}, nil
	}
	if stamp, err := time.Parse(time.RFC3339, value); err == nil {
		return sinceSpec{kind: sinceOperator, at: stamp}, nil
	}
	return sinceSpec{}, fmt.Errorf("--since needs a duration, boot, provision, or an RFC3339 time (got: %s)", value)
}

// applySince retargets a collected snapshot when --since names an edge. The
// collected "provision" boundary is already the artifact's own choice; "boot"
// forces the host's boot, and an operator stamp overrides the collected one.
func applySince(snapshot *audit.Snapshot, spec sinceSpec) error {
	switch spec.kind {
	case sinceBoot:
		if snapshot.Boot.IsZero() {
			return usagef(nil, "--since boot: the host boot time is unreadable")
		}
		snapshot.SetBoundary(audit.Boundary{
			Time: snapshot.Boot, Kind: "host", Source: "boot", Confidence: audit.MediumConfidence,
		})
	case sinceOperator:
		snapshot.SetBoundary(audit.Boundary{
			Time: spec.at, Kind: snapshot.Boundary.Kind, Source: "operator", Confidence: audit.HighConfidence,
		})
	}
	return nil
}

// renderOptions is the one place the text options are built.
func renderOptions(w io.Writer, flags auditFlags, filter audit.Filter) audit.RenderOptions {
	return audit.RenderOptions{
		Version:  buildVersion,
		Color:    isTerminal(w),
		Evidence: flags.evidence,
		Width:    terminalWidth(w),
		Filter:   filter,
	}
}
