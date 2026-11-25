// Package cli is the cobra application: one local audit model and the small
// readers that run in process on this host.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
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
		Long: "Read-only incident-response collection. With no command the audit runs over every surface; " +
			"scope words are surface names (systemd, profile, cron, ...), path prefixes (/var/www), " +
			"processes (/proc/36), or a leading ! exclusion. show prints one inventory without judging it; " +
			"cat and ls read files and directories in process; mtime lists a tree by change time; " +
			"watch reads live process and socket events.",
	}
	root.SetVersionTemplate("karma {{.Version}}\n")
	root.SuggestionsMinimumDistance = 2
	root.RunE = func(cmd *cobra.Command, args []string) error {
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
		newShowCmd(),
		newCatCmd(),
		newLsCmd(),
		newMtimeCmd(),
		newWatchCmd(),
		newListCmd(),
		newVersionCmd(version),
	)
	root.SetHelpCommand(helpCommand(root))
	return root
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit [scope...]",
		Short: "Audit the local host",
		Long: "Audit the local host in process. With no scope word the audit covers every surface; " +
			"scope words are surface names (systemd, profile, cron, ...), path prefixes (/var/www), " +
			"processes (/proc/36), or a leading ! exclusion.",
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
			"listeners, authority, mounts, or coverage. Scope words narrow it the way the audit's do.",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags, err := auditOptions(cmd.Flags())
			if err != nil {
				return usagef(cmd, "%s", err)
			}
			return runShow(cmd.Context(), cmd.OutOrStdout(), args, flags)
		},
	}
	addRunFlags(cmd)
	return cmd
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the audit vocabulary",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "modes     audit (default), show, cat, ls, mtime, watch")
			fmt.Fprintln(out, "show      activation, process, services, listeners, authority, mounts, coverage")
			fmt.Fprintln(out, "surfaces  "+strings.Join(surfaceWords, " "))
			fmt.Fprintln(out, "groups    persistence boot login schedule service device activity")
			fmt.Fprintln(out, "scope     a surface, a group, a path prefix, /proc/<pid>, or !word to exclude")
			return nil
		},
	}
}

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
