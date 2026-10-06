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
// whole, with row limits declared by the probe itself (a shape cap is the row
// set the tier asked for, a scan cap only bounds an open walk). Reading first
// aligns the winning tier's dialect (adapt) and then normalizes the body for the
// check (normalize); both run per section and carry the section title.
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
// tiers return promptly with the output they had already read; a session that
// reports its channel lost stops the queue the same way — the command line
// says so once instead of a failure panel per remaining check.
//
// The run's shared reads live in a store on the context (runstate), so checks
// that want the same expensive view of the host read it once between them.
func RunCatalog(ctx context.Context, sess session.Session, facts model.HostFacts, checks []*model.Check,
	options model.RunOptions, observer Observer) {
	ctx = runstate.WithStore(ctx)
	var g errgroup.Group
	g.SetLimit(max(1, options.Concurrency))
	for _, check := range checks {
		if sessionLost(sess) {
			break
		}
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			// re-checked here: the loss can land between the loop's check and
			// this worker's turn on the semaphore
			if sessionLost(sess) {
				return nil
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

// sessionLost reports whether the session's transport died mid-run (a channel
// that can no longer run anything): the queue stops, and in-flight checks keep
// the results they already produced. A session without the capability — the
// local channel — never stops early.
func sessionLost(sess session.Session) bool {
	lost, ok := sess.(session.LostChannel)
	return ok && lost.Lost()
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

// answeredTier is one tier of an answer set (model.Probe.Together) with the tier
// it came from, so its row cap can judge its own truncation.
type answeredTier struct {
	probe  model.Probe
	result model.RunResult
}

// runCheck walks the fallback chain once.
//
// The verdict decides: a tier that settled the question ends the walk — an
// answer, or a cut whose partial output is kept — while an unavailable or
// failed tier leaves the walk going. A tier marked Probe.Together answers with
// its neighbours rather than instead of them, so the set runs as a whole and its
// bodies join. If the last tier has both streams empty it stays silent; error
// text alone goes into the panel. A chain whose tiers were all unavailable
// (binary absent from the capability probe, or 127 at run time) is Skipped: the
// target's environment lacks the command, which is not a finding.
func runCheck(ctx context.Context, sess session.Session, facts model.HostFacts, check *model.Check, options model.RunOptions) *model.CheckResult {
	timeout := cmp.Or(check.Timeout, options.Timeout)
	ch := sess.Channel()

	var (
		unavailable bool
		skipped     []string
		failure     *probeFailure
		set         []answeredTier
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
		if name := probe.RequiredBin(); name != "" && !facts.Has(name) {
			unavailable = true
			skipped = append(skipped, probe.Label)
			continue
		}
		result := sess.Run(ctx, inv, timeout, probe.Cap)
		// A member of an answer set joins it whatever it reported — an answered
		// member's text is the check's, and a failed member's stderr is not a
		// verdict of its own while another member may still answer — unless the
		// environment lacks it, which is an unavailable tier like any other.
		if probe.Together && result.Verdict != model.VerdictUnavailable {
			set = append(set, answeredTier{probe: *probe, result: result})
			// A cut member ends the set: the source stopped answering, and the
			// members after it would read the same dead channel.
			if result.Verdict.Cut() {
				break
			}
			continue
		}
		switch {
		case result.Verdict.Settled():
			return commandResult(check, probe, result, skipped, resultOptions{
				timeout:   timeout,
				floor:     options.MinSeverity,
				truncated: result.Truncated && probe.Cap.Cut(),
			})
		case result.Verdict == model.VerdictUnavailable:
			unavailable = true
		default:
			if strings.TrimSpace(result.Stderr) != "" && failure == nil {
				failure = &probeFailure{probe: *probe, result: result, skipped: slices.Clone(skipped)}
			}
		}
		skipped = append(skipped, probe.Label)
	}

	if len(set) > 0 {
		return setResult(check, set, skipped, options, timeout)
	}
	if failure != nil {
		return commandResult(check, &failure.probe, failure.result, failure.skipped, resultOptions{
			timeout: timeout, floor: options.MinSeverity})
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

// setResult finishes an answer set: the members' bodies joined in declaration
// order, as one tier would have printed them. The set is answered when any
// member answered — the members are sources of one check, not alternatives to one
// another — so a member that failed while another answered is not the check's
// verdict. A set with no answer at all is the check's failure, carrying every
// member's stderr and the first exit code a member reported.
func setResult(check *model.Check, set []answeredTier, skipped []string, options model.RunOptions, timeout time.Duration) *model.CheckResult {
	joined := model.RunResult{Verdict: model.VerdictFailed, ExitCode: -1}
	for _, member := range set {
		switch {
		case member.result.Verdict == model.VerdictAnswered && joined.Verdict != model.VerdictAnswered:
			// The first answer names the set's verdict and exit code.
			joined.Verdict, joined.ExitCode = model.VerdictAnswered, member.result.ExitCode
		case member.result.Verdict.Cut() && joined.Verdict == model.VerdictFailed:
			// A cut is the set's own end, and a cut call has no exit code.
			joined.Verdict = member.result.Verdict
		}
	}
	var out, errText strings.Builder
	truncated := false
	for _, member := range set {
		if member.result.Stdout != "" {
			if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") {
				out.WriteByte('\n')
			}
			out.WriteString(member.result.Stdout)
		}
		errText.WriteString(member.result.Stderr)
		if member.result.Truncated && member.probe.Cap.Cut() {
			truncated = true
		}
		if joined.Verdict == model.VerdictFailed && joined.ExitCode < 0 && member.result.ExitCode >= 0 {
			joined.ExitCode = member.result.ExitCode
		}
	}
	joined.Stdout, joined.Stderr = out.String(), errText.String()
	labels := make([]string, 0, len(set))
	for _, member := range set {
		labels = append(labels, member.probe.Label)
	}
	probe := &model.Probe{Label: strings.Join(labels, " + ")}
	return commandResult(check, probe, joined, skipped, resultOptions{
		timeout: timeout, floor: options.MinSeverity, truncated: truncated})
}

// resultOptions is how the tier that won (or failed, or the set that answered)
// is finished: the deadline its note names, the run's severity floor, and
// whether the body was cut.
type resultOptions struct {
	timeout   time.Duration
	floor     model.SeverityFloor
	truncated bool
}

// commandResult finishes the tier that won (or failed): dialect alignment and
// body normalization first, then reading into a document.
func commandResult(check *model.Check, probe *model.Probe, result model.RunResult,
	skipped []string, opt resultOptions) *model.CheckResult {
	note := ""
	switch result.Verdict {
	case model.VerdictTimedOut:
		note = fmt.Sprintf("timeout (%gs)", opt.timeout.Seconds()) + keptTail(result)
	case model.VerdictInterrupted:
		note = "interrupted" + keptTail(result)
	case model.VerdictFailed:
		note = failureNote(result)
	}
	reading := reader.Analyze(result.Stdout, check.Rules, check.Filters,
		check.ScanBytes, opt.floor, transforms(probe, check)...)
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

// keptTail marks a cut-off tier that has output to keep: a body the deadline
// abandoned (a syscall that never returned) keeps nothing, and the note should
// not claim otherwise.
func keptTail(result model.RunResult) string {
	if strings.TrimSpace(result.Stdout) == "" {
		return ""
	}
	return ", partial output kept"
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

// transforms is the winning tier's dialect alignment followed by the check's
// body normalization: both shape one section, in this order, and either may be
// absent. Dialect alignment only produces text; stating spans up front is the
// check-level normalizer's job.
func transforms(probe *model.Probe, check *model.Check) []model.Normalizer {
	var all []model.Normalizer
	if probe.Adapt != nil {
		all = append(all, probe.Adapt)
	}
	if check.Normalize != nil {
		all = append(all, check.Normalize)
	}
	return all
}
