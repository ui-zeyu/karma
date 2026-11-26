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
	addRunFlags(cmd)
	return cmd
}

// runGraph builds one relation graph: a domain word draws that domain, and
// any other word names one object the graph grows from.
func runGraph(ctx context.Context, w io.Writer, word string, flags auditFlags) error {
	if !audit.IsGraphWord(word) {
		return runObjectGraph(ctx, w, word, flags)
	}
	plan, _ := audit.GraphPlan(word)
	snapshot, collectErr := collectSnapshot(ctx, plan, flags.timeout, flags.json)
	if snapshot == nil {
		return collectErr
	}
	if err := applySince(snapshot, flags.since); err != nil {
		return err
	}
	report := audit.Judge(snapshot, audit.Filter{MinSeverity: flags.minSeverity})
	graph, err := audit.BuildDomainGraph(word, snapshot, report.Findings, report.Coverage)
	if err != nil {
		return usagef(nil, "%s", err)
	}
	if flags.json {
		if err := audit.WriteGraphJSON(w, graph); err != nil {
			return err
		}
		return collectErr
	}
	audit.RenderGraph(w, graph, renderOptions(w, flags, audit.Filter{MinSeverity: flags.minSeverity}))
	return collectErr
}

// graphPlan is answered by the audit registry; the command stays a thin view
// over it.
