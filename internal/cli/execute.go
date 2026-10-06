// The execution flow shared by local and ssh: select checks, connect, collect
// facts, collect live, summarize.

package cli

import (
	"context"
	"io"
	"maps"
	"os"
	"slices"

	"golang.org/x/term"

	"karma/internal/checks"
	"karma/internal/facts"
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
func Execute(ctx context.Context, w io.Writer, transport session.Transport, options model.RunOptions, catalog []*model.Check) error {
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
	sess, err := transport.Open()
	if err != nil {
		return failf(2, "connection failed: %v", err)
	}
	defer sess.Close()

	bins := catalogBins(selected)
	factsValue := facts.CollectFor(ctx, transport.Platform(), sess, bins)
	width := terminalWidth(w)
	render.RenderHeader(w, sess.Name(), factsValue, width, options.MinSeverity, buildVersion)
	live := render.NewLiveObserver(w, selected, options.MaxLines, width, isTerminal(w))
	live.Start()
	defer live.Close()
	var observer runner.Observer = live
	if options.SaveDir != "" {
		saver := newSaveObserver(options.SaveDir, buildVersion, sess.Name(), factsValue, live)
		defer saver.finalize()
		observer = saver
	}
	runner.RunCatalog(ctx, sess, factsValue, selected, options, observer)
	return nil
}

// catalogBins is the union of the binaries every probe in the list requires,
// used for the capability probe: one PATH search per name.
func catalogBins(selected []*model.Check) []string {
	names := map[string]bool{}
	for _, check := range selected {
		for _, probe := range check.Probes {
			for _, name := range probe.RequiredBins() {
				names[name] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(names))
}
