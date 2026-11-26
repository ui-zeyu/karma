// The graph command prints one domain as relations, not as file content.

package cli

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"karma/internal/audit"
)

func newGraphCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graph <domain|object>",
		Short: "Print one relation graph",
		Long: "Print one relation graph. A domain word (identity, authority, network, packages, " +
			"boot, web, kernel) draws that domain: accounts and sudo grants, processes and peers, " +
			"package provenance, boot/login surfaces, web roots, kernel modules. Any other word " +
			"names one object — a unit, a pid, a path or a package — and the graph grows from it: " +
			"declared unit edges, the kernel's cgroup and open files, ELF and JAR dependencies, " +
			"the application tree, lexical path mentions, each file's package and content verdict. " +
			"Findings come first, then the nodes and edges the evidence built.",
		Example: "karma graph boot\nkarma graph ssh.service\nkarma graph pid:1234\nkarma graph /etc/ssh/sshd_config",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags, err := auditOptions(cmd.Flags())
			if err != nil {
				return usagef(cmd, "%s", err)
			}
			return runGraph(cmd.Context(), cmd.OutOrStdout(), args[0], flags)
		},
	}
	graphFlags(cmd.Flags())
	return cmd
}

// runGraph builds one relation graph: a domain word draws that domain, and
// any other word names one object the graph grows from.
func runGraph(ctx context.Context, w io.Writer, word string, flags auditFlags) error {
	module, spec, ok := audit.GraphTarget(word)
	if !ok {
		if _, isDomain := audit.ModuleForWord(word); isDomain {
			return usagef(nil, "graph has no domain view for %q; audit or show it instead", word)
		}
		if contains(surfaceWords, word) || contains(groupWords(), word) {
			return usagef(nil, "graph has no domain view for %q; name an object or a graph domain", word)
		}
		return runObjectGraph(ctx, w, word, flags)
	}
	plan := spec.Plan(module.Bit)
	snapshot, collectErr := collectSnapshot(ctx, plan, flags.timeout, flags.json)
	if snapshot == nil {
		return collectErr
	}
	if err := applySince(snapshot, flags.since); err != nil {
		return err
	}
	report := audit.Judge(snapshot, plan.Filter)
	view := spec.Build(snapshot)
	view.AttachFindings(spec.Domain, report.Findings, report.Coverage)
	if flags.json {
		if err := audit.WriteGraphJSON(w, view); err != nil {
			return err
		}
		return collectErr
	}
	audit.RenderGraph(w, view, renderOptions(w, flags, plan.Filter))
	return collectErr
}
