// The delegated run: a remote Linux channel collects through the karma binary it
// placed on the target, so the operator asks that binary for the whole run and
// reads its results as they arrive.
//
// Everything that decides what a run collects lives on the side that holds the
// data: the checks and their tiers, the fallback walk, the row caps, the
// concurrency and the per-check budgets. This side keeps the presentation — the
// catalog it selects from, the rules and floors it reads with, and the terminal
// it draws on — so the report of a remote run is the report of a local run on
// that host, with one implementation of the presentation wherever the collection
// happened.
//
// The stream is read while the run happens, so a panel is drawn the moment its
// check finishes rather than when the whole run ends.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"karma/internal/collect"
	"karma/internal/model"
	"karma/internal/runner"
	"karma/internal/session"
)

// collectorArgs is what the operator asks the collector for: its own local run in
// the protocol's JSON mode, with the selectors and the two options that decide
// what runs and how long it may take. The presentation options stay here — the
// floor, the line budget and the terminal belong to the report this end draws —
// and an option that was not set is left to the collector's own default, because
// `--timeout 0` would be refused rather than read as "no bound".
func collectorArgs(collector string, options model.RunOptions) []string {
	args := []string{collector, "local", "--json"}
	if options.Timeout > 0 {
		args = append(args, "--timeout", strconv.FormatFloat(options.Timeout.Seconds(), 'f', -1, 64))
	}
	if options.Concurrency > 0 {
		args = append(args, "--concurrency", strconv.Itoa(options.Concurrency))
	}
	return append(args, options.Selectors...)
}

// collectionBudget is how long one delegated run may take. The collector gives
// every check its own budget and runs them in batches, so the run's worst case is
// that many batches; one check's worth is on top for the channel's own setup and
// the last read. A zero budget leaves the call to the context, as everywhere
// else.
func collectionBudget(checks int, options model.RunOptions) time.Duration {
	if options.Timeout <= 0 {
		return 0
	}
	concurrency := max(1, options.Concurrency)
	batches := (checks + concurrency - 1) / concurrency
	return time.Duration(batches+1) * options.Timeout
}

// runDelegated runs one collection through the collector and hands every result
// to the observer as it arrives. The summary is the run's own account of how it
// ended; a collector that stopped rather than finishing comes back as an error,
// with the results that did arrive already drawn.
func runDelegated(ctx context.Context, sess session.Session, collector string, selected []*model.Check,
	options model.RunOptions, observer runner.Observer, warn io.Writer) (runner.Summary, error) {
	streamer, ok := sess.(session.Streamer)
	if !ok {
		return runner.Summary{}, failf(ExitInternal, "the %s channel cannot read a collector's stream", sess.Name())
	}
	budget := collectionBudget(len(selected), options)
	ctx, cancel := session.Within(ctx, budget)
	defer cancel()

	var (
		summary runner.Summary
		refused int
		reason  error
	)
	result := streamer.Stream(ctx, model.Call{Inv: model.NewCommand(collectorArgs(collector, options)...)},
		func(line string) {
			checkResult, err := readResult(selected, line, options)
			if err != nil {
				refused++
				reason = errors.Join(reason, err)
				return
			}
			summary.Results++
			observer.CheckStarted(checkResult.Check)
			observer.CheckFinished(checkResult.Check, checkResult)
		})

	// The collector's own stderr is karma's voice — a warning it printed, the
	// message of a panic boundary — so it travels to this end's warning stream
	// whatever the outcome below.
	if text := strings.TrimSpace(result.Stderr); text != "" {
		fmt.Fprintln(warn, text)
	}

	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return summary, failf(ExitEnvironment,
			"the collection did not finish within %s: %d of the %d selected checks were not collected",
			budget, len(selected)-summary.Results, len(selected))
	case ctx.Err() != nil:
		// Ctrl-C: the partial report still prints, and the caller's summary says
		// how much of it is missing.
		summary.Interrupted = true
	case sessionLost(sess):
		summary.LostChannel = true
	case result.ExitCode != 0:
		return summary, failf(ExitEnvironment, "the collector on the target failed: %s", collectorFailure(result))
	case summary.Results != len(selected):
		// The stream ended on its own with checks missing: the collector is
		// supposed to say why, so a short stream is a failure rather than an empty
		// panel per check that never arrived.
		return summary, failf(ExitEnvironment, "the collector's stream ended after %d of the %d selected checks",
			summary.Results, len(selected))
	}
	// A line this side could not read is only worth reporting when the stream was
	// not cut: a cut explains a half-written last line, and the panel-per-check
	// count above already says how much is missing.
	if refused > 0 {
		fmt.Fprintf(warn, "karma: %d result(s) of the collector's stream could not be read: %v\n", refused, reason)
	}
	return summary, nil
}

// readResult decodes one line of the stream against the catalog this end
// selected from.
func readResult(selected []*model.Check, line string, options model.RunOptions) (*model.CheckResult, error) {
	record, err := collect.Decode([]byte(line))
	if err != nil {
		return nil, err
	}
	return collect.ToCheckResult(selected, record, options)
}

// sessionLost reports whether the transport died under the run, the way the
// runner's own walk reads it.
func sessionLost(sess session.Session) bool {
	lost, ok := sess.(session.LostChannel)
	return ok && lost.Lost()
}

// collectorFailure describes a collector that stopped on its own: its status, and
// the first line of its own account of why.
func collectorFailure(result model.RunResult) string {
	head, _, _ := strings.Cut(strings.TrimSpace(result.Stderr), "\n")
	base := "no exit status"
	if result.ExitCode >= 0 {
		base = fmt.Sprintf("exit status %d", result.ExitCode)
	}
	if head != "" {
		return base + ": " + head
	}
	return base
}
