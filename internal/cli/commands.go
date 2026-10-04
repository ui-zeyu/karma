// Package cli is the cobra application: local, ssh, and list hang off the root
// command, and mtime is a subcommand of local and ssh. Every failure is written
// to stderr with the `karma: ` prefix by reportError.
package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"karma/internal/checks"
	"karma/internal/checks/linux"
	"karma/internal/model"
	"karma/internal/render"
	"karma/internal/session"
)

// Main wires up the command line and runs it; it returns the process exit code.
func Main(version string) int {
	root := newRootCmd(version)
	if err := root.Execute(); err != nil {
		return reportError(os.Stderr, err)
	}
	return 0
}

func newRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:           "karma",
		Short:         "Read-only incident-response collection: Linux over local or SSH, Windows on the local host.",
		Args:          rootArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// cobra only fills this default in its own "unknown command" hint, and
	// rootArgs calls SuggestionsFor directly, so set it explicitly (2 is
	// cobra's own convention)
	root.SuggestionsMinimumDistance = 2
	root.RunE = func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
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

func runLocalOrSSH(transport session.Transport, options model.RunOptions) error {
	return Execute(os.Stdout, transport, options, nil)
}

// runMtime is the mtime subcommand's body: one dynamic check appended after the
// directories. The local and ssh entry points share it.
func runMtime(transport session.Transport, dirs []string, options model.RunOptions) error {
	return Execute(os.Stdout, transport, options, []*model.Check{linux.HuntCheck(dirs)})
}

func newLocalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "local [selector...]",
		Short: "Collect read-only evidence from the local host",
		Long:  "Collect read-only evidence from the local host. Positional arguments are platform, aspect, or check names; all of them run when omitted.",
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := runOptions(cmd.Flags(), args)
			if err != nil {
				return err
			}
			return runLocalOrSSH(session.LocalTransport{}, options)
		},
	}
	addRunFlags(cmd)
	cmd.AddCommand(newMtimeCmd())
	return cmd
}

func newSSHCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh target [selector...]",
		Short: "Collect read-only evidence from an SSH target",
		Long: "Collect read-only evidence from an SSH target. Destinations follow OpenSSH: [user@]host or " +
			"ssh://[user@]host[:port] (bracket IPv6 addresses). Aspect names or check ids follow; all of " +
			"them run when omitted. Change-time clustering is written karma ssh TARGET mtime DIR...",
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
			if len(args) > 1 && args[1] == "mtime" {
				dirs := args[2:]
				if len(dirs) == 0 {
					return usagef(cmd, "mtime needs at least one directory: karma ssh TARGET mtime DIR...")
				}
				options, err := runOptions(cmd.Flags(), nil)
				if err != nil {
					return err
				}
				return runMtime(transport, dirs, options)
			}
			options, err := runOptions(cmd.Flags(), args[1:])
			if err != nil {
				return err
			}
			return runLocalOrSSH(transport, options)
		},
	}
	addRunFlags(cmd)
	addSSHFlags(cmd)
	return cmd
}

func newMtimeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mtime DIR...",
		Short: "Cluster change times for the given directories",
		Long: "Cluster change times for the given directories: deployments and installs form big clusters, " +
			"while a dropped trojan stands out as isolated files. The walk stays on each directory's own " +
			"filesystem and skips /proc, /sys and /dev. Under local it reads this host; over SSH " +
			"it is written karma ssh TARGET mtime DIR...",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "windows" {
				return fmt.Errorf("mtime clustering is a Linux check; Windows targets are not supported")
			}
			if len(args) == 0 {
				return usagef(cmd, "mtime needs at least one directory: karma local mtime DIR...")
			}
			options, err := runOptions(cmd.Flags(), nil)
			if err != nil {
				return err
			}
			return runMtime(session.LocalTransport{}, args, options)
		},
	}
	addRunFlags(cmd)
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
