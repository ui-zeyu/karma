// The execution flow shared by local and ssh: select checks, connect, collect
// facts, collect live, summarize.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"time"

	"golang.org/x/term"

	"karma/internal/checks"
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
// This is also the run's own damage boundary. Nothing above it recovers: main
// only turns the returned error into an exit status, so a panic on this path
// would print a Go stack trace, lose the report written so far, and leave the
// same status a failed connection uses. Here it becomes one message, the exit
// code that says the tool itself broke, and — with --save — a record of what
// went wrong beside the evidence.
func Execute(ctx context.Context, w io.Writer, transport session.Transport, options model.RunOptions, catalog []*model.Check) error {
	err := fault.Catch("collection", func() error { return execute(ctx, w, transport, options, catalog) })
	var crash *fault.Panic
	if !errors.As(err, &crash) {
		return err
	}
	saveCrash(options.SaveDir, crash)
	return failf(ExitInternal, "%s", crash.Error())
}

// execute is the run itself. The boundary above it owns the panic contract, so
// nothing here guards against one escaping.
func execute(ctx context.Context, w io.Writer, transport session.Transport, options model.RunOptions, catalog []*model.Check) error {
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

	bins := catalogBins(selected)
	factsValue := facts.CollectFor(ctx, transport.Platform(), sess, bins)
	if factsValue.ProbeCut {
		fmt.Fprintln(os.Stderr,
			"karma: the capability probe timed out: binaries it did not reach read as missing and their checks are skipped")
	}
	width := terminalWidth(w)
	render.RenderHeader(w, factsValue, render.HeaderInfo{
		Channel:   sess.Describe(),
		Version:   buildVersion,
		Started:   started,
		Selected:  len(selected),
		Total:     len(target),
		Selectors: SelectorTokens(options.Selectors),
		SaveDir:   options.SaveDir,
		Floor:     options.MinSeverity,
	}, width)
	live := render.NewLiveObserver(w, selected, options.MaxLines, width, isTerminal(w))
	live.Start()
	defer live.Close()
	var observer runner.Observer = live
	if options.SaveDir != "" {
		saver := newSaveObserver(options.SaveDir, buildVersion, sess.Name(), factsValue, live)
		defer saver.finalize()
		observer = saver
	}
	summary := runner.RunCatalog(ctx, sess, factsValue, selected, options, observer)
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

// catalogBins is the union of the binaries every probe in the list requires,
// used for the capability probe: one PATH search per name.
func catalogBins(selected []*model.Check) []string {
	names := map[string]bool{}
	for _, check := range selected {
		for _, step := range check.Steps {
			for _, probe := range step {
				if name := probe.RequiredBin(); name != "" {
					names[name] = true
				}
			}
		}
	}
	return slices.Sorted(maps.Keys(names))
}
