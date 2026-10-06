// The probe reader: run one probe of this host and hand back exactly what the
// tier produced. A placed collector answers its operator through this — one
// probe per call, the tier's text on stdout, the tier's standard error on
// stderr, the verdict as the process status — so the operator's channel reads
// back what a local run on the same host would have collected, and everything
// above the channel (assemble, adapt, normalize, rules, filters, render) stays
// one implementation.
//
// The mode adds nothing of its own to either stream, which is why it prints no
// summary: a line karma wrote there would be read as the tier's own. It also
// applies no row cap — the caller bounds the stream, so the truncation mark
// comes from the reader that stated the cap.

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/samber/lo"
	"github.com/spf13/cobra"

	"karma/internal/checks"
	"karma/internal/model"
	"karma/internal/session"
)

func newProbeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "probe CHECK PROBE",
		Short: "Run one probe and hand back what the tier produced",
		Long: "Run one probe of the local catalog and hand back exactly what the tier produced: its text on stdout, " +
			"its standard error on stderr, and its verdict as the process status — 127 for a tier this host does not " +
			"carry, which is what a collection's fallback chain reads to try the next tier. " +
			"This is the collector's own entry point: the remote channels collect through it, one probe at a time, " +
			"so the report is the one a local run on the same host would have drawn.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return usagef(cmd, "probe needs a check and a probe: karma local probe CHECK PROBE")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog := checks.ChecksFor(session.LocalTransport{}.Platform())
			return runProbe(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), catalog, args[0], args[1])
		},
	}
}

// runProbe answers one probe: the check named by checkID, the tier named by
// label. A name the catalog does not carry is a mistake the message explains,
// with the close names as its hint; anything else is the tier's own output and
// status.
func runProbe(ctx context.Context, w, warn io.Writer, catalog []*model.Check, checkID, label string) error {
	check, err := probeCheck(catalog, checkID)
	if err != nil {
		return err
	}
	probe, err := probeTier(check, label)
	if err != nil {
		return err
	}
	result := runTier(ctx, probe)
	if _, err := io.WriteString(w, result.Stdout); err != nil {
		return failf(ExitRead, "%v", err)
	}
	if _, err := io.WriteString(warn, result.Stderr); err != nil {
		return failf(ExitRead, "%v", err)
	}
	return silentError{code: ExitCode(exitForProbe(result.Verdict, result.ExitCode))}
}

// runTier runs one probe of this host through the local channel, the way a local
// run would. It is the tier's own invocation — a Native body runs here, in
// process — and an unavailable body answers with an empty body and a 127, the
// status a missing binary gives, which is what the walk that asked for it reads
// to fall to the next tier.
func runTier(ctx context.Context, probe model.Probe) model.RunResult {
	return session.LocalSession{}.Run(ctx, model.Call{Inv: probe.Inv})
}

// exitForProbe says the tier's verdict as the process status a channel reads
// back — session.verdictFor's rules in reverse. 127 with an empty stdout is the
// missing-command answer a script's own guard exits with, an answered tier keeps
// the status it earned (an empty answer is an answer, and the status travels
// with it), and every other ending is a non-zero status with nothing on stdout,
// so the panel names the stderr beside it.
func exitForProbe(verdict model.Verdict, exitCode int) int {
	switch verdict {
	case model.VerdictAnswered:
		return max(exitCode, 0)
	case model.VerdictUnavailable:
		return 127
	}
	return max(exitCode, 1)
}

// probeCheck resolves a check id, suggesting the close ones.
func probeCheck(catalog []*model.Check, id string) (*model.Check, error) {
	for _, check := range catalog {
		if check.ID == id {
			return check, nil
		}
	}
	ids := lo.Map(catalog, func(check *model.Check, _ int) string { return check.ID })
	return nil, fmt.Errorf("unknown check %q%s", id, closeMatches(id, ids))
}

// probeTier resolves a probe label within one check, suggesting the check's own
// labels: a label is unique inside its check, which is why the caller names both.
func probeTier(check *model.Check, label string) (model.Probe, error) {
	var labels []string
	for _, step := range check.Steps {
		for _, probe := range step {
			if probe.Label == label {
				return probe, nil
			}
			labels = append(labels, probe.Label)
		}
	}
	return model.Probe{}, fmt.Errorf("check %q has no probe %q%s", check.ID, label, closeMatches(label, labels))
}
