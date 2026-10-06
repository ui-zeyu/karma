// Package cli is the cobra application: local, ssh, ttyd, and list hang off
// the root command, the mtime and bootstrap modes are written after the channel
// command (and after the target on ssh and ttyd), and the cat, ls and probe
// readers hang under local — cat and ls present the host's own files, probe
// answers one catalog tier with the raw bytes a placed collector reports. Every
// failure is written to stderr with the `karma: ` prefix by reportError.
package cli

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"karma/internal/checks"
	"karma/internal/model"
	"karma/internal/render"
	"karma/internal/session"
)

// buildVersion is stamped by Main from the entry point's version.
var buildVersion = "dev"

// Main wires up the command line and runs it; it returns the process exit code.
// Ctrl-C (SIGINT/SIGTERM) cancels the run's context: collection stops promptly,
// in-flight checks keep the output they had already read, the partial report is
// still presented, and the exit code is 130 — which the run itself reports, so a
// signal that arrives after the last check cannot turn a complete report into an
// interrupted one.
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
		Short:         "Read-only incident-response collection: Linux over local, SSH, or a ttyd web terminal; Windows on the local host.",
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
		newTTYDCmd(),
		newListCmd(),
		newVersionCmd(version),
	)
	root.SetHelpCommand(helpCommand(root))
	return root
}

// runTargetCommand is the body of a command whose first argument is a target
// (ssh, ttyd): build the transport from that word, run the mode the rest name
// (mtime, bootstrap), and collect otherwise. Both channels go through here, so
// their argument handling cannot drift apart.
func runTargetCommand(cmd *cobra.Command, args []string, form string,
	build func(flags *pflag.FlagSet, target string) (session.Transport, error)) error {
	transport, err := build(cmd.Flags(), args[0])
	if err != nil {
		return err
	}
	rest := args[1:]
	if dirs, ok := modeArgs(rest, "mtime"); ok {
		return runMtimeMode(cmd, transport, dirs, form)
	}
	if extra, ok := modeArgs(rest, "bootstrap"); ok {
		return runBootstrapMode(cmd, transport, extra)
	}
	options, err := runOptions(cmd.Flags(), rest)
	if err != nil {
		return err
	}
	return Execute(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), transport, options, nil)
}

// modeArgs splits a channel command's mode word out of its positional
// arguments: the mode is the first word the channel's own form leaves (the front
// under local, after the target under ssh and ttyd), and the words after it
// belong to the mode. Both modes are written the same way, so their argument
// handling cannot drift apart.
func modeArgs(args []string, mode string) ([]string, bool) {
	if len(args) == 0 || args[0] != mode {
		return nil, false
	}
	return args[1:], true
}

// runBootstrapMode is the bootstrap form's entry from either channel: it puts
// this binary on the target and stops there, so a collection's selectors and
// run options have nothing to act on.
func runBootstrapMode(cmd *cobra.Command, transport session.Transport, extra []string) error {
	if len(extra) > 0 {
		return usagef(cmd, "bootstrap only uploads the binary; run it on the target yourself (unexpected: %s)",
			strings.Join(extra, " "))
	}
	return runBootstrap(cmd.Context(), transport, placeOptionsFrom(cmd.Flags()))
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
	return runMtime(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), transport, dirs, options)
}

// runMtime is the mtime mode's body: one dynamic check appended after the
// directories. Which platforms have a tree to walk is the catalog registry's
// answer, so the command line carries no platform of its own.
func runMtime(ctx context.Context, w, warn io.Writer, transport session.Transport, dirs []string, options model.RunOptions) error {
	check, err := checks.HuntCheckFor(transport.Platform(), dirs)
	if err != nil {
		return err
	}
	return Execute(ctx, w, warn, transport, options, []*model.Check{check})
}

func newLocalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "local [selector...]",
		Short: "Collect read-only evidence from the local host",
		Long: "Collect read-only evidence from the local host. Positional arguments are platform, aspect, or check names; " +
			"all of them run when omitted, and a leading ! on a name excludes those checks. " +
			"Change-time clustering is written karma local mtime DIR... " +
			"The built-in readers never run the host's own binaries: " +
			"karma local cat FILE..., karma local ls [PATH...] (the current directory when no path is given). " +
			"One probe answers on its own through karma local probe CHECK PROBE.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dirs, ok := modeArgs(args, "mtime"); ok {
				return runMtimeMode(cmd, session.LocalTransport{}, dirs, "local")
			}
			options, err := runOptions(cmd.Flags(), args)
			if err != nil {
				return err
			}
			return Execute(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), session.LocalTransport{}, options, nil)
		},
	}
	addRunFlags(cmd)
	cmd.AddCommand(newCatCmd(), newLsCmd(), newProbeCmd())
	return cmd
}

func newSSHCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh target [selector...]",
		Short: "Collect read-only evidence from an SSH target",
		Long: "Collect read-only evidence from an SSH target. Destinations follow OpenSSH: [user@]host or " +
			"ssh://[user@]host[:port] (bracket IPv6 addresses). Aspect names or check ids follow; all of " +
			"them run when omitted, and a leading ! on a name excludes those checks. " +
			"Change-time clustering is written karma ssh TARGET mtime DIR.... " +
			"A collection places this binary on the target and runs its tiers through it — in process, so no " +
			"shell and no host tool is in the path — and keeps the copy for the next run. " +
			"karma ssh TARGET bootstrap places it and stops, printing the path.",
		Args: atLeastOneArg("ssh needs a target: [user@]host or ssh://[user@]host[:port]"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTargetCommand(cmd, args, "ssh TARGET", buildSSHTransport)
		},
	}
	addRunFlags(cmd)
	addPlaceFlags(cmd)
	addSSHFlags(cmd)
	return cmd
}

// newTTYDCmd collects through a ttyd web terminal: one websocket endpoint the
// operator already exposes, typed into as a second client.
func newTTYDCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ttyd target [selector...]",
		Short: "Collect read-only evidence from a ttyd web terminal",
		Long: "Collect read-only evidence from a host reached through a ttyd web terminal. " +
			"The target is the websocket endpoint: ws://host[:port] or wss://host[:port], " +
			"with ttyd's default port 7681 for a bare host and user:pass@ as the credential " +
			"(ttyd's -c). karma connects as a second client and types its collection line " +
			"into the terminal ttyd spawns for it, so the server must accept client input: " +
			"ttyd from 1.7.4 needs -W/--writable. The channel is Linux only, like ssh. " +
			"Aspect names or check ids follow; all of them run when omitted, and a leading ! " +
			"on a name excludes those checks. " +
			"Change-time clustering is written karma ttyd TARGET mtime DIR.... " +
			"A collection types this binary into the terminal, keeps it there, and runs its tiers through it " +
			"in process. karma ttyd TARGET bootstrap places it and stops, printing the path.",
		Args: atLeastOneArg("ttyd needs a target: ws://host[:port] or host[:port]"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTargetCommand(cmd, args, "ttyd TARGET", buildTTYDTransport)
		},
	}
	addRunFlags(cmd)
	addPlaceFlags(cmd)
	addTTYDFlags(cmd)
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
