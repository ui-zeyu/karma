// Package runner orchestrates execution: run checks concurrently and fall back
// through probe tiers. Results travel back through the Observer on completion;
// the presentation layer places the panels in catalog order itself.
//
// A tier whose Dual has no branch for the session's channel is skipped
// silently — it is not part of that channel's chain. Tier fallback covers
// availability discovered at run time only — a missing binary, a 127 — never
// which side of the wire karma runs on.
//
// Runner only depends on session.Session's Run callback: it knows neither SSH
// nor any concrete command. The tier that wins is sent to the target as a
// whole, with row limits declared by the probe itself (head is the wanted
// shape, line_limit only caps open scans). Reading first aligns the winning
// tier's dialect (adapt) and then normalizes the body for the check
// (normalize); both run per section and carry the section title.
package runner

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"karma/internal/model"
	"karma/internal/reader"
	"karma/internal/runstate"
	"karma/internal/session"
)

// Observer is the run-progress callback, provided by the presentation layer.
// Callbacks may enter from different goroutines; implementations must be safe
// for that (the live observer funnels everything into one render goroutine).
type Observer interface {
	CheckStarted(check *model.Check)
	CheckFinished(check *model.Check, result *model.CheckResult)
}

// RunCatalog runs the checks concurrently in catalog order. Each check calls
// the Observer as soon as it finishes in its own goroutine; catalog order is
// released by the presentation layer by check index, and no conclusions are
// gathered here. A cancelled context stops queuing new checks and in-flight
// tiers return promptly with the output they had already read.
//
// The run's shared reads live in a store on the context (runstate), so checks
// that want the same expensive view of the host read it once between them.
func RunCatalog(ctx context.Context, sess session.Session, facts model.HostFacts, checks []*model.Check,
	options model.RunOptions, observer Observer) {
	ctx = runstate.WithStore(ctx)
	var g errgroup.Group
	g.SetLimit(max(1, options.Concurrency))
	for _, check := range checks {
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			runObserver(observer, func() { observer.CheckStarted(check) })
			result := recoverPanic(check, func() *model.CheckResult {
				return runCheck(ctx, sess, facts, check, options)
			})
			// A rendering panic in CheckFinished is already caught by emit's
			// internal fallback; reaching here means unexpected internal damage
			// — dropping one frame beats dragging down the whole run.
			runObserver(observer, func() { observer.CheckFinished(check, result) })
			return nil
		})
	}
	_ = g.Wait()
}

// recoverPanic keeps one broken check from dragging down the whole run.
func recoverPanic(check *model.Check, run func() *model.CheckResult) (result *model.CheckResult) {
	defer func() {
		if problem := recover(); problem != nil {
			result = &model.CheckResult{
				Check:   check,
				Outcome: model.Failed,
				Note:    fmt.Sprintf("check panic: %v", problem),
			}
		}
	}()
	return run()
}

// runObserver insures the observer callback: a presentation-layer panic drops
// only this step, not the checks that have not finished.
func runObserver(observer Observer, call func()) {
	defer func() { _ = recover() }()
	call()
}

// probeFailure is the first failing tier with error output on the chain; it
// goes into the panel at the end.
type probeFailure struct {
	probe   model.Probe
	result  model.RunResult
	skipped []string // skip chain up to this tier, excluding this tier
}

// runCheck walks the fallback chain once.
//
// Exit code 0 or existing stdout stays. 127, and a non-zero exit with empty
// stdout, moves to the next tier. A timeout or cancellation keeps the output
// that was cut off and does not move on; a cancelled context stops walking the
// chain. If the last tier has both streams empty it stays silent; error text
// alone goes into the panel. A chain whose tiers were all unavailable (binary
// absent from the capability probe, or 127 at run time) is Skipped: the
// target's environment lacks the command, which is not a finding.
func runCheck(ctx context.Context, sess session.Session, facts model.HostFacts, check *model.Check, options model.RunOptions) *model.CheckResult {
	timeout := cmp.Or(check.Timeout, options.Timeout)
	ch := sess.Channel()

	var (
		unavailable bool
		skipped     []string
		failure     *probeFailure
	)
	for i := range check.Probes {
		if ctx.Err() != nil {
			break
		}
		probe := &check.Probes[i]
		inv := probe.InvocationFor(ch)
		if inv == nil {
			continue // this tier exists on the other channel only
		}
		if !facts.HasAll(probe.RequiredBins()) {
			unavailable = true
			skipped = append(skipped, probe.Label)
			continue
		}
		// head is the shape this tier wants (stopping once it has enough rows
		// counts as success); line_limit only caps open scans
		result := sess.Run(ctx, inv, timeout, cmp.Or(probe.Head, probe.LineLimit))
		switch {
		case result.TimedOut || result.Answered():
			// "truncated" is marked for an explicit line_limit and the byte
			// safety valve; head's stop-when-satisfied is the shape this
			// command wants and is not marked (catalog invariant: Head and
			// LineLimit are mutually exclusive)
			truncated := result.Truncated && probe.Head == 0
			return commandResult(check, probe, result, skipped, timeout, noteOptions{truncated: truncated})
		case result.ExitCode == 127:
			unavailable = true
		case strings.TrimSpace(result.Stderr) != "" && failure == nil:
			failure = &probeFailure{probe: *probe, result: result, skipped: slices.Clone(skipped)}
		}
		skipped = append(skipped, probe.Label)
	}

	if failure != nil {
		return commandResult(check, &failure.probe, failure.result, failure.skipped, timeout,
			noteOptions{failure: true})
	}
	if unavailable {
		return &model.CheckResult{
			Check:         check,
			Outcome:       model.Skipped,
			SkippedLabels: skipped,
		}
	}
	return &model.CheckResult{Check: check, Outcome: model.Collected, SkippedLabels: skipped}
}

type noteOptions struct {
	truncated bool
	failure   bool
}

// commandResult finishes the tier that won (or failed): dialect alignment and
// body normalization first, then reading into a document.
func commandResult(check *model.Check, probe *model.Probe, result model.RunResult,
	skipped []string, timeout time.Duration, opt noteOptions) *model.CheckResult {
	note := ""
	switch {
	case result.TimedOut:
		note = fmt.Sprintf("timeout (%gs), partial output kept", timeout.Seconds())
	case result.Interrupted:
		note = "interrupted, partial output kept"
	case opt.failure:
		note = failureNote(result)
	}
	reading := reader.Analyze(result.Stdout, check.Rules, check.Filters,
		readingTransform(probe, check.Normalize), check.ScanBytes)
	reading.Truncated = reading.Truncated || opt.truncated
	// Stderr from a zero exit is incidental noise; only a non-zero exit keeps
	// it alongside the body
	stderr := result.Stderr
	if result.ExitCode == 0 {
		stderr = ""
	}
	return &model.CheckResult{
		Check:         check,
		ProbeLabel:    probe.Label,
		Outcome:       model.Collected,
		SkippedLabels: skipped,
		// Evidence is what the target actually sent: the raw stdout, before the
		// reading layer's byte cap, section split, and normalization
		Raw:      result.Stdout,
		Stderr:   stderr,
		Note:     note,
		Document: reading,
	}
}

// failureNote is the note on a failing tier: exit code first, the first stderr
// line after it.
func failureNote(result model.RunResult) string {
	head, _, _ := strings.Cut(strings.TrimSpace(result.Stderr), "\n")
	base := "command returned no exit code"
	if result.ExitCode >= 0 {
		base = fmt.Sprintf("exit code %d", result.ExitCode)
	}
	if head != "" {
		return base + ": " + head
	}
	return base
}

// readingTransform runs the winning probe's dialect alignment first and the
// check's body normalization after; both within a section. Dialect alignment
// only produces text; stating spans up front is the check-level normalizer's
// job.
func readingTransform(probe *model.Probe, normalize model.Normalizer) model.Normalizer {
	adapt, then := probe.Adapt, normalize
	switch {
	case adapt == nil:
		return then
	case then == nil:
		return adapt
	}
	return func(title string, body string) *model.Shaped {
		aligned := adapt(title, body)
		if aligned != nil {
			body = aligned.Text
		}
		return then(title, body)
	}
}
