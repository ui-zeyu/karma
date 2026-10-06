// The probe reader: run one probe and print its raw result. It is the
// collector's own entry point — a placed collector answers its operator one
// probe at a time, and these are the bytes that operator's pipeline then
// assembles, adapts, normalizes, grades and renders, exactly as it would for a
// local run — and it is also how a person reads the wire by hand on a target.
//
// The mode exists on the local channel alone: it names the side of the wire the
// collection happens on.

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
	"karma/internal/wire"
)

func newProbeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe CHECK PROBE",
		Short: "Run one probe and print its raw result",
		Long: "Run one probe of the local catalog and print the result as it stands. " +
			"This is the collector's own entry point: the remote channels collect through it, one probe at a " +
			"time, so the operator reads the bytes a local run on the same host would have produced. " +
			"--json prints one line of the collector's wire format instead of the raw body.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return usagef(cmd, "probe needs a check and a probe: karma local probe CHECK PROBE")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			asJSON, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			catalog := checks.ChecksFor(session.LocalTransport{}.Platform())
			return runProbe(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), catalog, args[0], args[1], asJSON)
		},
	}
	cmd.Flags().Bool("json", false, "print the result as one line of the collector's wire format")
	return cmd
}

// runProbe answers one probe: the check named by checkID, the tier named by
// label. A name the catalog does not carry is a mistake the message explains,
// with the close names as its hint.
//
// The answer is a value, never a failure of this command: a tier that could not
// run is the verdict and the exit code the operator's walk reads, so the process
// that answered an envelope exits 0 while saying the tier was unavailable.
func runProbe(ctx context.Context, w, warn io.Writer, catalog []*model.Check, checkID, label string, asJSON bool) error {
	check, err := probeCheck(catalog, checkID)
	if err != nil {
		return err
	}
	probe, err := probeTier(check, label)
	if err != nil {
		return err
	}
	result := runTier(ctx, probe)
	if asJSON {
		line, err := wire.New(check.ID, probe.Label, result).Line()
		if err != nil {
			return failf(ExitInternal, "%v", err)
		}
		_, err = w.Write(line)
		return err
	}
	fmt.Fprintf(warn, "probe %s %s: %s (exit %d)\n", check.ID, probe.Label, result.Verdict, result.ExitCode)
	_, err = io.WriteString(w, result.Stdout)
	return err
}

// runTier runs one probe of this host through the local channel, the way a local
// run would. A tier this channel does not carry answers unavailable with an
// empty body and a 127 — the status a missing binary gives — which is what the
// walk that asked for it reads to fall to the next tier.
func runTier(ctx context.Context, probe model.Probe) model.RunResult {
	inv := probe.InvocationFor(model.ChanLocal)
	if inv == nil {
		return model.RunResult{
			Verdict:  model.VerdictUnavailable,
			Stderr:   model.ErrTierUnavailable.Error(),
			ExitCode: 127,
		}
	}
	return session.LocalSession{}.Run(ctx, model.Call{Inv: inv, Cap: probe.Cap})
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
// labels: the label is only unique inside its check, which is why the operator
// names both.
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
