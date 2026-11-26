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

	"karma/internal/audit"
)

// runAudit is the default action of the command and of `karma audit`.
func runAudit(ctx context.Context, w io.Writer, words []string, flags auditFlags) error {
	parsed, err := parseScope(words)
	if err != nil {
		return usagef(nil, "%s", err)
	}
	if flags.json && flags.evidence {
		return usagef(nil, "--evidence prints the text inventories after a text report; the machine-readable inventories are \"karma show <section> --json\"")
	}
	snapshot, collectErr := collectSnapshot(ctx, parsed.plan(), flags.timeout, flags.json)
	if snapshot == nil {
		return collectErr
	}
	if err := applySince(snapshot, flags.since); err != nil {
		return err
	}
	report := audit.Judge(snapshot, parsed.filter(flags.minSeverity))
	if flags.json {
		if err := audit.WriteJSON(w, report); err != nil {
			return err
		}
		return collectErr
	}
	audit.Render(w, report, renderOptions(w, flags, parsed.filter(audit.Info)))
	return collectErr
}

// runShow prints one collected inventory without judging it. The section
// decides what the collection reads; the scope's units, pids and paths
// narrow the rows to the relations they name.
func runShow(ctx context.Context, w io.Writer, words []string, flags auditFlags) error {
	section, ok := audit.SectionFor(words[0])
	if !ok {
		return usagef(nil, "unknown show target %q (%s)", words[0], strings.Join(audit.ShowWords(), ", "))
	}
	parsed, err := parseScope(words[1:])
	if err != nil {
		return usagef(nil, "%s", err)
	}
	snapshot, collectErr := collectSnapshot(ctx, section.Plan(parsed.plan()), flags.timeout, flags.json)
	if snapshot == nil {
		return collectErr
	}
	if err := applySince(snapshot, flags.since); err != nil {
		return err
	}
	options := renderOptions(w, flags, parsed.filter(audit.Info))
	view := audit.NewView(snapshot, options.Filter)
	if flags.json {
		if err := audit.WriteShowJSON(w, view, section, words[0], options); err != nil {
			return err
		}
		return collectErr
	}
	audit.RenderShow(w, view, section, words[0], options)
	return collectErr
}

// runObjectGraph prints one object's relation graph and the findings that
// touch it. The seed is parsed before the collection, so a mistyped selector
// fails in milliseconds rather than after the budget.
func runObjectGraph(ctx context.Context, w io.Writer, word string, flags auditFlags) error {
	seed, err := audit.ParseGraphSeed(word)
	if err != nil {
		return usagef(nil, "%s", err)
	}
	snapshot, collectErr := collectSnapshot(ctx, audit.ObjectGraphPlan(seed), flags.timeout, flags.json)
	if snapshot == nil {
		return collectErr
	}
	if err := applySince(snapshot, flags.since); err != nil {
		return err
	}
	view, err := audit.BuildObjectGraph(ctx, snapshot, seed, flags.minSeverity)
	if err != nil {
		return usagef(nil, "%s", err)
	}
	if flags.json {
		if err := audit.WriteGraphJSON(w, view); err != nil {
			return err
		}
		return collectErr
	}
	audit.RenderGraph(w, view, renderOptions(w, flags, audit.Filter{MinSeverity: flags.minSeverity}))
	return collectErr
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
	json        bool
	evidence    bool
	minSeverity audit.Severity
	since       string
	timeout     time.Duration
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

// sinceTime reads --since: empty and "auto" keep the collected boundary;
// "boot" and "provision" are the same boundary by another name; a duration
// answers now minus it; an RFC3339 stamp is absolute.
// applySince retargets a collected snapshot when --since names an edge.
func applySince(snapshot *audit.Snapshot, since string) error {
	seconds, ok, err := sinceTime(since)
	if err != nil {
		return usagef(nil, "%s", err)
	}
	if ok {
		snapshot.SetBoundary(audit.Boundary{
			Time: seconds, Kind: snapshot.Boundary.Kind, Source: "operator", Confidence: audit.HighConfidence,
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

func sinceTime(value string) (time.Time, bool, error) {
	switch value {
	case "", "auto", "boot", "provision":
		return time.Time{}, false, nil
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return time.Now().Add(-duration), true, nil
	}
	if stamp, err := time.Parse(time.RFC3339, value); err == nil {
		return stamp, true, nil
	}
	return time.Time{}, false, fmt.Errorf("--since needs a duration, boot, provision, or an RFC3339 time (got: %s)", value)
}
