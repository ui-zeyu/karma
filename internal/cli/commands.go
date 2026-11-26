// Package cli is the cobra application: one local audit model and the small
// readers that run in process on this host.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"karma/internal/audit"
)

var buildVersion = "dev"

// Main wires up the command line and runs it; it returns the process exit code.
func Main(version string) int {
	ctx, stop := interruptible()
	defer stop()
	buildVersion = version
	root := newRootCmd(version)
	if err := root.ExecuteContext(ctx); err != nil {
		return reportError(os.Stderr, err)
	}
	return int(ExitOK)
}

func newRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:           "karma [scope...]",
		Short:         "Read-only incident-response collection for the local Linux host.",
		Version:       version,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: "Read-only incident-response audit of the local Linux host: judge the artifact delta, " +
			"the activation surfaces and the kernel state, and print the findings with their evidence. " +
			"With no command every bounded domain is audited; scope words narrow it to a domain, a " +
			"surface, a path, a pid or a unit. graph reads the same collected facts as relations; " +
			"show prints one raw inventory unjudged.",
	}
	root.SetVersionTemplate("karma {{.Version}}\n")
	root.SuggestionsMinimumDistance = 2
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			if err := retiredWord(args[0]); err != nil {
				return usagef(cmd, "%s", err)
			}
		}
		flags, err := auditOptions(cmd.Flags())
		if err != nil {
			return usagef(cmd, "%s", err)
		}
		return runAudit(cmd.Context(), cmd.OutOrStdout(), args, flags)
	}
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return usagef(cmd, "%s", flagErrorText(err))
	})
	root.CompletionOptions.HiddenDefaultCmd = true
	addRunFlags(root)
	root.AddCommand(
		newAuditCmd(),
		newGraphCmd(),
		newShowCmd(),
		newCatCmd(),
		newLsCmd(),
		newCtimeCmd(),
		newWatchCmd(),
		newListCmd(),
		newVersionCmd(version),
	)
	root.SetHelpCommand(helpCommand(root))
	rootHelp(root)
	return root
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit [scope...]",
		Short: "Audit the local host",
		Long: "Audit the local host in process. With no scope word the audit covers every bounded " +
			"domain; the SCOPE panel lists the words that narrow it.",
		Example: "karma audit\nkarma audit persistence\nkarma audit /var/www",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags, err := auditOptions(cmd.Flags())
			if err != nil {
				return usagef(cmd, "%s", err)
			}
			return runAudit(cmd.Context(), cmd.OutOrStdout(), args, flags)
		},
	}
	addRunFlags(cmd)
	return cmd
}

func newShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <section> [scope...]",
		Short: "Print one collected inventory without judging it",
		Long: "Print one collected inventory without judging it: activation, process, services, " +
			"listeners, connections, kernel, authority, mounts, trail, or coverage. A section prints every " +
			"row it collected, and the scope words narrow it by the relations its rows answer: a " +
			"unit narrows the services, processes, sockets and activation edges it owns; a path " +
			"narrows the paths; a pid narrows the processes and their sockets.",
		Example: "karma show activation\nkarma show listeners\nkarma show coverage",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			flags, err := auditOptions(cmd.Flags())
			if err != nil {
				return usagef(cmd, "%s", err)
			}
			return runShow(cmd.Context(), cmd.OutOrStdout(), args, flags)
		},
	}
	showFlags(cmd.Flags())
	return cmd
}

// retiredWord catches a word a merged-away command used to own. At the root
// every unknown word is a scope word, and "profile" is also a startup
// surface, so without this guard `karma profile ssh.service` would silently
// audit the login surface instead of naming the object's graph.
func retiredWord(word string) error {
	if word == "profile" {
		return fmt.Errorf(`"profile" moved: karma graph <unit|pid|path|package> draws the object's relations (the login surface is karma audit profile)`)
	}
	return nil
}

// newListCmd prints the CLI's vocabulary as the same page every command
// wears: the description band, then one quiet panel per word family.
func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the audit vocabulary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			writePage(cmd.OutOrStdout(), cmd, listSections(cmd), listFooter)
			return nil
		},
	}
}

// listSections is the listing's whole table, in reading order. Each row comes
// from the registry that defines the words, so the page cannot drift from the
// grammar the commands parse.
func listSections(cmd *cobra.Command) []pageSection {
	line := func(words ...string) []string { return []string{strings.Join(words, " ")} }
	modes := []string{"audit (default)"}
	for _, sub := range cmd.Root().Commands() {
		if !sub.IsAvailableCommand() || sub.Name() == "completion" {
			continue
		}
		modes = append(modes, sub.Name())
	}
	return []pageSection{
		{"start", startRows},
		{"modes", line(modes...)},
		{"domains", line(audit.DomainWords()...)},
		{"graph", line(audit.GraphWords()...)},
		{"show", line(audit.ShowWords()...)},
		{"surfaces", line(surfaceWords...)},
		{"groups", line(groupWords()...)},
	}
}

// listFooter is the one sentence the vocabulary answers to.
const listFooter = "Use a word with any command: a domain, a surface, a group, a path prefix, /proc/<pid>, a unit name, or a leading ! exclusion."

func newVersionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the karma version",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { cmd.Printf("karma %s\n", version); return nil },
	}
}

func atLeastOneArg(spelling string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return usagef(cmd, "%s", spelling)
		}
		return nil
	}
}
