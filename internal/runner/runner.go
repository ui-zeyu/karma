// Execution orchestration: run checks concurrently and fall back through
// probe tiers. Results travel back through the Observer on completion; the
// presentation layer places the panels in catalog order itself.
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
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"

	"karma/internal/model"
	"karma/internal/reader"
	"karma/internal/session"
)

// Observer is the run-progress callback, provided by the presentation layer.
// Callbacks may enter from different goroutines; implementations bring their
// own lock.
type Observer interface {
	CheckStarted(check *model.Check)
	CheckFinished(check *model.Check, result *model.CheckResult)
}

// RunCatalog runs the checks concurrently in catalog order. Each check calls
// the Observer as soon as it finishes in its own goroutine; catalog order is
// released by the presentation layer by check index, and no conclusions are
// gathered here.
func RunCatalog(sess session.Session, facts model.HostFacts, checks []*model.Check,
	options model.RunOptions, observer Observer) {
	var g errgroup.Group
	g.SetLimit(max(1, options.Concurrency))
	for _, check := range checks {
		g.Go(func() error {
			runObserver(observer, func() { observer.CheckStarted(check) })
			result := recoverPanic(check, func() *model.CheckResult {
				return runCheck(sess, facts, check, options)
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
// stdout, moves to the next tier. A timeout keeps the output that was cut off
// and does not move on. If the last tier has both streams empty it stays
// silent; error text alone goes into the panel.
func runCheck(sess session.Session, facts model.HostFacts, check *model.Check, options model.RunOptions) *model.CheckResult {
	timeout := cmp.Or(check.Timeout, options.Timeout)

	var (
		missing  []string
		skipped  []string
		notFound []string
		failure  *probeFailure
	)
	for i := range check.Probes {
		probe := &check.Probes[i]
		if lacks := facts.Missing(probe.RequiredBins()); len(lacks) > 0 {
			missing = lo.Uniq(append(missing, lacks...))
			skipped = append(skipped, probe.Label)
			continue
		}
		// head is the shape this tier wants (stopping once it has enough rows
		// counts as success); line_limit only caps open scans
		result := sess.Run(probe.Inv, timeout, cmp.Or(probe.Head, probe.LineLimit))
		switch {
		case result.TimedOut || result.Answered():
			// "truncated" is marked for an explicit line_limit and the byte
			// safety valve; head's stop-when-satisfied is the shape this
			// command wants and is not marked (catalog invariant: Head and
			// LineLimit are mutually exclusive)
			truncated := result.Truncated && probe.Head == 0
			return commandResult(check, probe, result, skipped, timeout, noteOptions{truncated: truncated})
		case result.ExitCode == 127:
			notFound = append(notFound, probe.Label)
		case strings.TrimSpace(result.Stderr) != "" && failure == nil:
			failure = &probeFailure{probe: *probe, result: result, skipped: slices.Clone(skipped)}
		}
		skipped = append(skipped, probe.Label)
	}

	if failure != nil {
		return commandResult(check, &failure.probe, failure.result, failure.skipped, timeout,
			noteOptions{failure: true})
	}
	if len(missing) > 0 || len(notFound) > 0 {
		return &model.CheckResult{
			Check:         check,
			Outcome:       model.Skipped,
			SkippedLabels: skipped,
			Missing:       missing,
			NotFound:      notFound,
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
	case opt.failure:
		note = failureNote(result)
	}
	reading := reader.Analyze(result.Stdout, check.Rules, check.Filters,
		readingTransform(probe, check.Normalize), check.ScanBytes)
	document := reading.Document
	// The byte cap and the line cap share the same "truncated" mark
	document.Truncated = document.Truncated || opt.truncated
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
		Output:        reading.Source,
		Stderr:        stderr,
		Note:          note,
		Document:      document,
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
