// Package cli is the cobra application: one channel command (local, ssh,
// ttyd), one audit model, and the small viewers that read a target directly.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"karma/internal/session"
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
		Use:           "karma",
		Short:         "Read-only incident-response collection: Linux over local, SSH, or a ttyd web terminal.",
		Version:       version,
		Args:          rootArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("karma {{.Version}}\n")
	root.SuggestionsMinimumDistance = 2
	root.RunE = func(cmd *cobra.Command, args []string) error { return cmd.Help() }
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return usagef(cmd, "%s", flagErrorText(err))
	})
	root.CompletionOptions.HiddenDefaultCmd = true
	root.AddCommand(
		newLocalCmd(),
		newSSHCmd(),
		newTTYDCmd(),
		newListCmd(),
		newVersionCmd(version),
	)
	root.SetHelpCommand(helpCommand(root))
	return root
}

func newLocalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "local [audit|show|mtime] [scope...]",
		Short: "Audit the local host",
		Long: "Audit the local host in process. With no mode word the command audits every surface; " +
			"scope words are surface names (systemd, profile, cron, ...), path prefixes (/var/www), " +
			"processes (/proc/36), or a leading ! exclusion. show prints one inventory without judging it. " +
			"cat and ls read files and directories in process; mtime lists a tree by change time; " +
			"watch reads live process and socket events.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLocal(cmd, args)
		},
	}
	addRunFlags(cmd)
	cmd.AddCommand(newCatCmd(), newLsCmd(), newWatchCmd(), newMtimeCmd())
	return cmd
}

func newSSHCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh [flags] TARGET [audit|show|mtime|bootstrap] [scope...]",
		Short: "Audit a Linux host over SSH",
		Long: "Audit a Linux host over SSH. The target is [user@]host or ssh://[user@]host[:port]. " +
			"With no mode word the command audits every surface; scope words are surface names, " +
			"path prefixes, /proc/<pid>, or a leading ! exclusion. show prints one inventory; " +
			"mtime lists a tree by change time; bootstrap places this binary on the target.",
		Args: atLeastOneArg("ssh needs a target: [user@]host or ssh://[user@]host[:port]"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTargetCommand(cmd, args, "ssh", buildSSHTransport)
		},
	}
	addRunFlags(cmd)
	addSSHFlags(cmd)
	return cmd
}

func newTTYDCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ttyd [flags] TARGET [audit|show|mtime|bootstrap] [scope...]",
		Short: "Audit a Linux host through a ttyd web terminal",
		Long: "Audit a Linux host through a ttyd web terminal. The target is ws://host[:port] or " +
			"wss://host[:port]; user:pass@ sets the credential. ttyd 1.7.4 and later need -W/--writable. " +
			"The modes are the ssh channel's.",
		Args: atLeastOneArg("ttyd needs a target: ws://host[:port] or host[:port]"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTargetCommand(cmd, args, "ttyd", buildTTYDTransport)
		},
	}
	addRunFlags(cmd)
	addTTYDFlags(cmd)
	return cmd
}

func runTargetCommand(cmd *cobra.Command, args []string, channel string, build func(*pflag.FlagSet, string) (session.Transport, error)) error {
	transport, err := build(cmd.Flags(), args[0])
	if err != nil {
		return err
	}
	rest := args[1:]
	mode, words := splitMode(rest)
	switch mode {
	case "bootstrap":
		return runBootstrap(cmd.Context(), cmd.OutOrStdout(), transport)
	case "audit":
		flags, err := auditOptions(cmd.Flags())
		if err != nil {
			return usagef(cmd, "%s", err)
		}
		return runAudit(cmd.Context(), cmd.OutOrStdout(), transport, false, channel+" "+args[0], words, flags)
	case "show":
		flags, err := auditOptions(cmd.Flags())
		if err != nil {
			return usagef(cmd, "%s", err)
		}
		return runShow(cmd.Context(), cmd.OutOrStdout(), transport, false, words, flags)
	case "mtime":
		return runMtime(cmd.Context(), cmd.OutOrStdout(), transport, words)
	default:
		return usagef(cmd, "unknown mode %q (audit, show, mtime, bootstrap)", mode)
	}
}

func runLocal(cmd *cobra.Command, args []string) error {
	mode, words := splitMode(args)
	switch mode {
	case "audit":
		flags, err := auditOptions(cmd.Flags())
		if err != nil {
			return usagef(cmd, "%s", err)
		}
		return runAudit(cmd.Context(), cmd.OutOrStdout(), session.LocalTransport{}, true, "local", words, flags)
	case "show":
		flags, err := auditOptions(cmd.Flags())
		if err != nil {
			return usagef(cmd, "%s", err)
		}
		return runShow(cmd.Context(), cmd.OutOrStdout(), session.LocalTransport{}, true, words, flags)
	default:
		return usagef(cmd, "unknown mode %q (audit, show; cat, ls, mtime and watch are subcommands)", mode)
	}
}

// splitMode picks the first word when it names a mode; every other list is an
// audit scope.
func splitMode(words []string) (string, []string) {
	if len(words) == 0 {
		return "audit", nil
	}
	switch words[0] {
	case "audit", "show", "mtime", "bootstrap":
		return words[0], words[1:]
	}
	return "audit", words
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the audit vocabulary",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "modes     audit, show, mtime, watch (local), cat/ls (local), bootstrap (ssh/ttyd)")
			fmt.Fprintln(out, "show      activation, process, services, listeners, authority, coverage")
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
