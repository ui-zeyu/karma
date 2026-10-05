// Package cli is the cobra application: local, ssh, and list hang off the root
// command, the mtime mode is written after the channel command (and after the
// target on ssh), and the cat and ls built-in readers hang under local. Every
// failure is written to stderr with the `karma: ` prefix by reportError.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"karma/internal/checks"
	"karma/internal/checks/linux"
	"karma/internal/model"
	"karma/internal/render"
	"karma/internal/session"
)

// buildVersion is stamped by Main from the entry point's version; --save's
// manifest records it.
var buildVersion = "dev"

// Main wires up the command line and runs it; it returns the process exit code.
// Ctrl-C (SIGINT/SIGTERM) cancels the run's context: collection stops promptly,
// in-flight checks keep the output they had already read, the partial report is
// still presented, and the exit code is 130.
func Main(version string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	buildVersion = version
	root := newRootCmd(version)
	if err := root.ExecuteContext(ctx); err != nil {
		return reportError(os.Stderr, err)
	}
	if ctx.Err() != nil {
		return reportError(os.Stderr, failf(130, "interrupted"))
	}
	return 0
}

func newRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:           "karma",
		Short:         "Read-only incident-response collection: Linux over local or SSH, Windows on the local host.",
		Version:       version,
		Args:          rootArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// --version prints the same line the version subcommand prints.
	root.SetVersionTemplate("karma {{.Version}}\n")
	// cobra only fills this default in its own "unknown command" hint, and
	// rootArgs calls SuggestionsFor directly, so set it explicitly (2 is
	// cobra's own convention)
	root.SuggestionsMinimumDistance = 2
	root.RunE = func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	// Help and errors render through the skeleton styles; the help func set on
	// the root is inherited by every subcommand.
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		styledHelp(cmd)
	})
	// Flag errors come from pflag; wrap them so Main appends the usage block
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return usagef(cmd, "%s", flagErrorText(err))
	})
	// Completion scripts are cobra's own feature: kept, but out of the help
	// listing (its text is English boilerplate)
	root.CompletionOptions.HiddenDefaultCmd = true
	root.AddCommand(
		newLocalCmd(),
		newSSHCmd(),
		newListCmd(),
		newVersionCmd(version),
	)
	root.SetHelpCommand(helpCommand(root))
	return root
}

func runLocalOrSSH(ctx context.Context, transport session.Transport, options model.RunOptions) error {
	return Execute(ctx, os.Stdout, transport, options, nil)
}

// mtimeArgs splits the mtime form out of a channel command's positional
// arguments: they follow the word "mtime" — at the front under local, after the
// target under ssh — so both channels tell the mode apart the same way.
func mtimeArgs(args []string) ([]string, bool) {
	if len(args) == 0 || args[0] != "mtime" {
		return nil, false
	}
	return args[1:], true
}

// runMtimeMode is the mtime form's entry from either channel: dirs are the words
// after "mtime" and form is how that channel's command line is spelled, for the
// usage error when none was given.
func runMtimeMode(cmd *cobra.Command, transport session.Transport, dirs []string, form string) error {
	if len(dirs) == 0 {
		return usagef(cmd, "mtime needs at least one directory: karma %s mtime DIR...", form)
	}
	options, err := runOptions(cmd.Flags(), nil)
	if err != nil {
		return err
	}
	return runMtime(cmd.Context(), transport, dirs, options)
}

// runMtime is the mtime mode's body: one dynamic check appended after the
// directories. Clustering walks a Linux tree, so a channel that is not Linux
// (the local one on Windows) has nothing to walk.
func runMtime(ctx context.Context, transport session.Transport, dirs []string, options model.RunOptions) error {
	if transport.Platform() != model.Linux {
		return fmt.Errorf("mtime clustering is a Linux check; Windows targets are not supported")
	}
	return Execute(ctx, os.Stdout, transport, options, []*model.Check{linux.HuntCheck(dirs)})
}

func newLocalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "local [selector...]",
		Short: "Collect read-only evidence from the local host",
		Long: "Collect read-only evidence from the local host. Positional arguments are platform, aspect, or check names; " +
			"all of them run when omitted, and a leading ! on a name excludes those checks. " +
			"Change-time clustering is written karma local mtime DIR... " +
			"The built-in readers never run the host's own binaries: " +
			"karma local cat FILE..., karma local ls [PATH...] (the current directory when no path is given).",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dirs, ok := mtimeArgs(args); ok {
				return runMtimeMode(cmd, session.LocalTransport{}, dirs, "local")
			}
			options, err := runOptions(cmd.Flags(), args)
			if err != nil {
				return err
			}
			return runLocalOrSSH(cmd.Context(), session.LocalTransport{}, options)
		},
	}
	addRunFlags(cmd)
	cmd.AddCommand(newCatCmd(), newLsCmd())
	return cmd
}

func newSSHCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh target [selector...]",
		Short: "Collect read-only evidence from an SSH target",
		Long: "Collect read-only evidence from an SSH target. Destinations follow OpenSSH: [user@]host or " +
			"ssh://[user@]host[:port] (bracket IPv6 addresses). Aspect names or check ids follow; all of " +
			"them run when omitted, and a leading ! on a name excludes those checks. " +
			"Change-time clustering is written karma ssh TARGET mtime DIR...",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usagef(cmd, "ssh needs a target: [user@]host or ssh://[user@]host[:port]")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			transport, err := buildSSHTransport(cmd.Flags(), args[0])
			if err != nil {
				return err
			}
			if dirs, ok := mtimeArgs(args[1:]); ok {
				return runMtimeMode(cmd, transport, dirs, "ssh TARGET")
			}
			options, err := runOptions(cmd.Flags(), args[1:])
			if err != nil {
				return err
			}
			return runLocalOrSSH(cmd.Context(), transport, options)
		},
	}
	addRunFlags(cmd)
	addSSHFlags(cmd)
	return cmd
}

// newVersionCmd prints the release version; the build stamps it with -X main.version.
func newVersionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the karma version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Printf("karma %s\n", version)
			return nil
		},
	}
}

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [selector...]",
		Short: "List the check catalog",
		Long: "List the check catalog of both platforms, grouped by platform and aspect; positional arguments are " +
			"platform, aspect, or check names; all of them are listed when omitted.",
		RunE: func(cmd *cobra.Command, args []string) error {
			selected, err := SelectChecks(args, checks.AllChecks())
			if err != nil {
				return err
			}
			render.RenderListTable(os.Stdout, selected, terminalWidth(os.Stdout))
			return nil
		},
	}
	return cmd
}
