// Package runner orchestrates execution: run checks concurrently and fall back
// through each check's walk of steps. Results travel back through the Observer
// on completion; the presentation layer places the panels in catalog order
// itself.
//
// Fallback covers availability discovered at run time only — a missing binary,
// a 127, a body that cannot run on this host — and never the source: the channel
// states that once (Channel.Source), and the walk below holds only its source's
// tiers, so the other side's are not tried as a fallback, and neither is the
// other side's absence a reason to change source.
//
// The budget belongs to the walk, not to one tier's call: one deadline covers
// every step of a check, and the channel's own setup inside it, so the number a
// panel's note names is the whole answer's, and the worst case of a run is
// ceil(checks / concurrency) × budget.
//
// Runner only depends on session.Session's Run method: it knows neither SSH nor
// any concrete command. The step that wins is sent to the target as a whole,
// with row limits declared by the probe itself (a shape cap is the row set the
// tier asked for, a scan cap only bounds an open walk). The winning tier's
// output is handed to the reading layer (internal/reader), which owns everything
// from there to the document the presentation draws.
package runner

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"karma/internal/fault"
	"karma/internal/model"
	"karma/internal/reader"
	"karma/internal/runstate"
	"karma/internal/session"
	"karma/internal/textutil"
)

// Observer is the run-progress callback, provided by the presentation layer.
// Callbacks may enter from different goroutines; implementations must be safe
// for that (the live observer funnels everything into one render goroutine).
type Observer interface {
	CheckStarted(check *model.Check)
	CheckFinished(check *model.Check, result *model.CheckResult)
	// Damaged reports one piece of the run that could not be presented at all: a
	// rendering panic, a failed write. The run carries on, so the report can say
	// what it lost instead of losing the reader too.
	Damaged(check *model.Check, err error)
}

// Summary is what a run observed about its own completeness: how many checks
// produced a result, and the two ways the queue can end early. The command line
// reports from it, so the exit status and the message come from what the run saw
// rather than from a context read after the fact.
type Summary struct {
	// Results is the number of checks that produced a result.
	Results int
	// Interrupted is set when cancellation (Ctrl-C) ended the queue.
	Interrupted bool
	// LostChannel is set when the transport died under the run.
	LostChannel bool
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
func RunCatalog(ctx context.Context, sess session.Session, checks []*model.Check,
	options model.RunOptions, observer Observer) Summary {
	ctx = runstate.WithStore(ctx)
	var (
		g       errgroup.Group
		results atomic.Int64
		lost    atomic.Bool
	)
	g.SetLimit(max(1, options.Concurrency))
	for _, check := range checks {
		if sessionLost(sess) {
			lost.Store(true)
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
				lost.Store(true)
				return nil
			}
			guardedObserver(observer, check, func() { observer.CheckStarted(check) })
			result, damage := fault.Result("check "+check.ID, func() *model.CheckResult {
				return runCheck(ctx, sess, check, options)
			})
			if damage != nil {
				// One broken check fails alone: the panel names the boundary,
				// which beats ending the process and the whole report with it.
				result = &model.CheckResult{Check: check, Outcome: model.Failed, Note: damage.Error()}
			}
			results.Add(1)
			guardedObserver(observer, check, func() { observer.CheckFinished(check, result) })
			return nil
		})
	}
	_ = g.Wait()
	return Summary{
		Results:     int(results.Load()),
		Interrupted: ctx.Err() != nil,
		LostChannel: lost.Load() || sessionLost(sess),
	}
}

// guardedObserver insures one observer callback: a presentation panic drops that
// step alone, and the observer hears about it — a report that silently lost a
// panel is worse than one that says so.
func guardedObserver(observer Observer, check *model.Check, call func()) {
	err := fault.Catch("presentation", func() error { call(); return nil })
	if err == nil {
		return
	}
	// The reporter is presentation too: if it panics in turn, this one line is
	// what is lost, and the run keeps going.
	_ = fault.Catch("presentation", func() error { observer.Damaged(check, err); return nil })
}

// sessionLost reports whether the session's transport died mid-run (a channel
// that can no longer run anything): the queue stops, and in-flight checks keep
// the results they already produced. A session without the capability — the
// local channel — never stops early.
func sessionLost(sess session.Session) bool {
	lost, ok := sess.(session.LostChannel)
	return ok && lost.Lost()
}

// defaultFileCap bounds a file list whose probe declares no cap: a list that
// names more files than this is volume rather than evidence, the same judgement
// an open scan's own cap makes, and each file costs the channel a round trip.
const defaultFileCap = 200

// probeFailure is the first step of the walk that failed with error output; it
// goes into the panel at the end.
type probeFailure struct {
	step     model.Step
	label    string
	result   model.RunResult
	sections []model.BodySection
	skipped  []string // skip chain up to this step, excluding it
}

// answeredTier is one probe of a step with the sections it answered with, so its
// own row cap can judge its truncation.
type answeredTier struct {
	probe    model.Probe
	result   model.RunResult
	sections []model.BodySection
}

// runCheck walks one check's steps once.
//
// The verdict decides: a step that settled the question ends the walk — an
// answer, or a cut whose partial output is kept — while an unavailable or
// failed step leaves the walk going. A step of several probes answers as a whole
// (model.Step). If the last step has both streams empty the check stays silent;
// error text alone goes into the panel. A walk whose steps were all unavailable
// (a 127, or a body that cannot run here) is Skipped: the target's environment
// lacks the command, which is not a finding.
func runCheck(ctx context.Context, sess session.Session, check *model.Check, options model.RunOptions) *model.CheckResult {
	budget := cmp.Or(check.Timeout, options.Timeout)
	ctx, cancel := session.Within(ctx, budget)
	defer cancel()

	// The run walks one source's tiers — the one this channel reads with — so a
	// check can hold both sources' tiers side by side, and a check with none of
	// this source's is skipped whole.
	steps := check.StepsFor(sess.Channel().Source())
	if len(steps) == 0 {
		return &model.CheckResult{
			Check:         check,
			Outcome:       model.Skipped,
			SkippedLabels: check.TierLabels(),
		}
	}

	var (
		unavailable bool
		skipped     []string
		failure     *probeFailure
	)
	for _, step := range steps {
		if ctx.Err() != nil {
			break
		}
		members := stepMembers(ctx, sess, step)
		joined, sections, label := joinStep(members)
		switch {
		case joined.Verdict.Settled():
			return finishStep(check, step, joined, sections, label, skipped, options, budget)
		case joined.Verdict == model.VerdictUnavailable:
			unavailable = true
		default:
			if failure == nil && strings.TrimSpace(joined.Stderr) != "" {
				failure = &probeFailure{step: step, label: label, result: joined,
					sections: sections, skipped: slices.Clone(skipped)}
			}
		}
		skipped = append(skipped, label)
	}

	if failure != nil {
		return finishStep(check, failure.step, failure.result, failure.sections, failure.label,
			failure.skipped, options, budget)
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

// stepMembers runs every probe of one step. Whether the target has the tier's
// tool is the tier's own answer when it runs — ErrTierUnavailable in a body, a
// 127 from a missing binary — which is what the chain above reads.
func stepMembers(ctx context.Context, sess session.Session, step model.Step) []answeredTier {
	members := make([]answeredTier, 0, len(step))
	for _, probe := range step {
		members = append(members, runProbe(ctx, sess, probe))
		if members[len(members)-1].result.Verdict.Cut() {
			// The channel — or the walk's budget — is gone: the members after
			// this one would read the same dead source.
			break
		}
	}
	return members
}

// runProbe is one probe's answer: the sections it read, and the call result the
// walk's verdict reads. A probe of one invocation answers with one section under
// the probe's own title; a file list answers with one section per path, titled
// with the path.
func runProbe(ctx context.Context, sess session.Session, probe model.Probe) answeredTier {
	if probe.Files == nil {
		result := sess.Run(ctx, model.Call{Inv: probe.Inv, Cap: probe.Cap})
		return answeredTier{probe: probe, result: result, sections: []model.BodySection{{
			Title:    probe.Title,
			Text:     result.Stdout,
			Records:  result.Records,
			Adapt:    probe.Adapt,
			Assemble: probe.Assemble,
		}}}
	}
	return readFiles(ctx, sess, probe)
}

// readFiles runs a file-list probe: the list call names the paths, then one call
// reads each. The list itself is the tier's answer — a listing that failed fails
// the probe — while a read that failed leaves its section empty, the way the
// per-file shell read's own error text was dropped.
//
// The probe's cap bounds the number of files: a list longer than it is a cut,
// like an open scan's own cap, and the files past it are not read at all.
func readFiles(ctx context.Context, sess session.Session, probe model.Probe) answeredTier {
	listing := sess.Run(ctx, model.Call{Inv: probe.Files.List})
	if !listing.Verdict.Settled() {
		return answeredTier{probe: probe, result: listing}
	}
	paths := slices.DeleteFunc(textutil.CollectLines(listing.Stdout), func(path string) bool {
		return path == ""
	})
	limit := probe.Cap.Rows
	if limit <= 0 {
		limit = defaultFileCap
	}
	cut := len(paths) > limit
	if cut {
		paths = paths[:limit]
		// The body is presented as cut by the same rule an open scan's cap uses,
		// so the panel states the list was longer than the probe allows.
		probe.Cap = model.Scan(limit)
	}
	result := listing
	result.Stdout, result.Records, result.Truncated = "", nil, cut
	// The files are a body of their own: what a section lost is the reading's
	// business, and the list's stderr stays the probe's.
	sections := make([]model.BodySection, 0, len(paths))
	for _, path := range paths {
		read := sess.Run(ctx, model.Call{Inv: probe.Files.Read(path)})
		if read.Verdict.Cut() {
			// The channel or the walk's budget is gone: the files after this one
			// would read the same dead source, and what arrived is kept.
			result.Verdict, result.Truncated = read.Verdict, true
			break
		}
		sections = append(sections, model.BodySection{
			Title:    path,
			Text:     ended(read.Stdout),
			Records:  read.Records,
			Adapt:    probe.Adapt,
			Assemble: probe.Assemble,
		})
	}
	return answeredTier{probe: probe, result: result, sections: sections}
}

// ended gives one file's body the terminator the per-file shell read used to
// supply: a body whose last line carries no newline would otherwise glue onto
// the next section's header in the evidence.
func ended(text string) string {
	if text == "" || strings.HasSuffix(text, "\n") {
		return text
	}
	return text + "\n"
}

// joinStep merges one step's members into the step's own answer: the sections in
// declaration order, and a label naming what ran. The step answered when any
// member answered — the members are sources of one answer, so a member that
// failed while another answered is not the check's verdict — and a step whose
// members all reported the environment lacking it is unavailable, like any
// single tier. Nothing answered and not all were unavailable means the step
// failed, carrying every member's stderr and the first exit code one reported.
func joinStep(members []answeredTier) (model.RunResult, []model.BodySection, string) {
	joined := model.RunResult{Verdict: model.VerdictFailed, ExitCode: -1}
	for _, member := range members {
		switch {
		case member.result.Verdict == model.VerdictAnswered && joined.Verdict != model.VerdictAnswered:
			// The first answer names the step's verdict and exit code.
			joined.Verdict, joined.ExitCode = model.VerdictAnswered, member.result.ExitCode
		case member.result.Verdict.Cut() && joined.Verdict == model.VerdictFailed:
			// A cut is the step's own end, and a cut call has no exit code.
			joined.Verdict = member.result.Verdict
		}
	}
	if joined.Verdict == model.VerdictFailed && allUnavailable(members) {
		joined.Verdict = model.VerdictUnavailable
	}
	// One pass over the members gathers the sections, the error text, the
	// truncation mark, the first exit code, and the label.
	var (
		sections  []model.BodySection
		errText   strings.Builder
		labels    = make([]string, 0, len(members))
		truncated bool
	)
	for _, member := range members {
		sections = append(sections, member.sections...)
		errText.WriteString(member.result.Stderr)
		if member.result.Truncated && member.probe.Cap.Cut() {
			truncated = true
		}
		if joined.Verdict == model.VerdictFailed && joined.ExitCode < 0 && member.result.ExitCode >= 0 {
			joined.ExitCode = member.result.ExitCode
		}
		labels = append(labels, member.probe.Label)
	}
	joined.Stderr, joined.Truncated = errText.String(), truncated
	// A body of one section of fields keeps them for the result stream; a step
	// that answered with text (or with several sections) states no fields of its
	// own — the records a tier read are the tier's, and a joined body is text.
	if len(sections) == 1 {
		joined.Records = sections[0].Records
	}
	return joined, sections, joinLabels(labels)
}

// joinLabels names what ran: the members' labels in walk order, each run of
// identical ones named once, so a step that is one tier's several parts names
// that tier rather than repeating it.
func joinLabels(labels []string) string {
	return strings.Join(slices.Compact(labels), " + ")
}

// allUnavailable reports whether every member of a step said the environment
// lacks it, which is what makes the step unavailable rather than failed.
func allUnavailable(members []answeredTier) bool {
	for _, member := range members {
		if member.result.Verdict != model.VerdictUnavailable {
			return false
		}
	}
	return len(members) > 0
}

// finishStep finishes the step that ended the walk (or failed it): the note the
// verdict deserves, then dialect alignment and body normalization, then reading
// into a document.
func finishStep(check *model.Check, step model.Step, joined model.RunResult, sections []model.BodySection,
	label string, skipped []string, options model.RunOptions, budget time.Duration) *model.CheckResult {
	note := ""
	switch joined.Verdict {
	case model.VerdictTimedOut:
		note = fmt.Sprintf("timeout (%gs)", budget.Seconds()) + keptTail(sections)
	case model.VerdictInterrupted:
		note = "interrupted" + keptTail(sections)
	case model.VerdictFailed:
		note = failureNote(joined)
	}
	body := model.Body{Sections: sections}
	reading := reader.Read(model.ReadRequest{
		Check:     check,
		Step:      step,
		Body:      body,
		Floor:     options.MinSeverity,
		Truncated: joined.Truncated,
	})
	// Stderr from a zero exit is incidental noise; only a non-zero exit keeps
	// it alongside the body
	stderr := joined.Stderr
	if joined.ExitCode == 0 {
		stderr = ""
	}
	return &model.CheckResult{
		Check:         check,
		ProbeLabel:    label,
		Outcome:       model.Collected,
		SkippedLabels: skipped,
		// Evidence is what the target actually sent: the raw stdout before the
		// reading layer's byte cap, section split, and normalization — or, for a
		// tier that read fields, the readable rendering of those fields.
		Raw:      reader.Evidence(body),
		Records:  joined.Records,
		Stderr:   stderr,
		Note:     note,
		Document: reading,
	}
}

// keptTail marks a cut-off step that has output to keep: a body the deadline
// abandoned (a syscall that never returned) keeps nothing, and the note should
// not claim otherwise.
func keptTail(sections []model.BodySection) string {
	for _, section := range sections {
		if strings.TrimSpace(section.Text) != "" || section.Records != nil {
			return ", partial output kept"
		}
	}
	return ""
}

// failureNote is the note on a failing step: exit code first, the first stderr
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
