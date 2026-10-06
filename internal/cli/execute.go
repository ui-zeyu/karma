// The execution flow shared by local and ssh: select checks, connect, collect
// facts, collect live, summarize.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"

	"karma/internal/checks"
	"karma/internal/collect"
	"karma/internal/facts"
	"karma/internal/fault"
	"karma/internal/model"
	"karma/internal/render"
	"karma/internal/runner"
	"karma/internal/session"
)

const fallbackWidth = 100

// terminalFile returns the file handle when writer is a terminal.
func terminalFile(w io.Writer) (*os.File, bool) {
	file, ok := w.(*os.File)
	return file, ok && term.IsTerminal(int(file.Fd()))
}

func isTerminal(w io.Writer) bool {
	_, ok := terminalFile(w)
	return ok
}

// terminalWidth is the terminal width; a non-terminal falls back to a default.
func terminalWidth(w io.Writer) int {
	file, ok := terminalFile(w)
	if !ok {
		return fallbackWidth
	}
	if size, _, err := term.GetSize(int(file.Fd())); err == nil && size > 0 {
		return size
	}
	return fallbackWidth
}

// Execute is one full collection run. A nil catalog uses the platform's check
// catalog; the mtime subcommand passes its own list. A cancelled context stops
// the run: in-flight checks keep the output they had already read, and the
// partial report is still presented. The returned error is printed by the
// command-line layer.
//
// w carries the report and warn the run's own warnings — a capability probe cut
// short, an evidence write that failed, the crash record below — so a caller
// that captured the report can also read why something is missing from it, and
// neither stream is a hard-coded process handle.
//
// This is also the run's own damage boundary. Nothing above it recovers: main
// only turns the returned error into an exit status, so a panic on this path
// would print a Go stack trace, lose the report written so far, and leave the
// same status a failed connection uses. Here it becomes one message and the exit
// code that says the tool itself broke.
func Execute(ctx context.Context, w, warn io.Writer, transport session.Transport, options model.RunOptions, catalog []*model.Check) error {
	err := fault.Catch("collection", func() error { return execute(ctx, w, warn, transport, options, catalog) })
	var crash *fault.Panic
	if !errors.As(err, &crash) {
		return err
	}
	return failf(ExitInternal, "%s", crash.Error())
}

// execute is the run itself. The boundary above it owns the panic contract, so
// nothing here guards against one escaping.
func execute(ctx context.Context, w, warn io.Writer, transport session.Transport, options model.RunOptions, catalog []*model.Check) error {
	started := time.Now()
	target := catalog
	if target == nil {
		target = checks.ChecksFor(transport.Platform())
	}
	selected, err := SelectChecks(options.Selectors, target)
	if err != nil {
		return err
	}

	// CLI boundary: a connection failure (authentication failure, rejected host
	// key) is one environmental failure, with exit code 2
	sess, err := transport.Open(ctx)
	if err != nil {
		return failf(ExitEnvironment, "connection failed: %v", err)
	}
	defer sess.Close()

	// A remote Linux channel collects through the binary it places on the
	// target: one copy per run, reused when one is already there and proved to
	// be this build. A channel that cannot carry an upload — or a target that is
	// not Linux, where karma has no in-process bodies — runs the tiers itself.
	if delegator, ok := sess.(session.Delegator); ok && transport.Platform() == model.Linux {
		path, _, err := placeCollector(ctx, sess, placeOptions{find: options.FindDir, place: options.PlaceDir})
		if err != nil {
			return failf(ExitEnvironment, "%v", err)
		}
		delegator.UseCollector(path)
	}

	factsValue := facts.CollectFor(ctx, transport.Platform(), sess)
	if factsValue.ProbeCut {
		fmt.Fprintln(warn,
			"karma: the capability probe timed out: a tool it did not reach reads as absent, so the host facts may be thinner than they look")
	}
	// Two ways to hand the operator what the run saw. The report draws each panel
	// as its check finishes; the collector protocol writes one JSON object per
	// check instead, which is what a run asks for when it is going to be read by
	// another karma rather than by a person. The walk, the concurrency and the
	// budgets are the same either way.
	var (
		observer runner.Observer
		stream   *collect.Writer
	)
	if options.JSON {
		stream = collect.NewWriter(w)
		observer = stream
	} else {
		width := terminalWidth(w)
		render.RenderHeader(w, factsValue, render.HeaderInfo{
			Channel:   sess.Describe(),
			Version:   buildVersion,
			Started:   started,
			Selected:  len(selected),
			Total:     len(target),
			Selectors: SelectorTokens(options.Selectors),
			Floor:     options.MinSeverity,
		}, width)
		live := render.NewLiveObserver(w, selected, options.MaxLines, width, isTerminal(w))
		live.Start()
		defer live.Close()
		observer = live
	}
	summary := runner.RunCatalog(ctx, sess, selected, options, observer)
	// A stream that stopped early is a result the reader is missing, so the run
	// says so rather than ending as if it had delivered the whole set.
	if stream != nil && stream.Err() != nil {
		return failf(ExitRead, "the result stream could not be written: %v", stream.Err())
	}
	// The run reports how it ended: the exit status and the message come from
	// what it saw, so a signal that lands after the last check cannot turn a
	// complete report into an interrupted one, and a run that stopped early says
	// how much it is missing.
	switch {
	case summary.Interrupted:
		return failf(ExitInterrupted, "interrupted: %d of the %d selected checks were not collected",
			len(selected)-summary.Results, len(selected))
	case summary.LostChannel:
		return failf(ExitEnvironment, "channel lost mid-run: %d of the %d selected checks were not collected",
			len(selected)-summary.Results, len(selected))
	}
	return nil
}
