// watch: the live process and socket views under the local command.
//
// The two subcommands are views of one event stream. Each names the source it
// opened and the cadence on stderr, so a piped stdout stays a clean stream; the
// events themselves carry structural flags (unowned, admin layer, interpreter
// plus script), never a name-based verdict.

package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"karma/internal/watch"
)

func newWatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch live process and socket events",
		Long: "Watch the kernel's process and socket tables as they change. socket prints new sockets " +
			"(including the TIME-WAIT row a short connection leaves), proc prints process starts and exits. " +
			"Both run until Ctrl-C or --duration, print one line per event, and annotate each event with " +
			"structural facts: an executable the package database does not own, an administrator-layer " +
			"working directory, or an interpreter carrying a script. An exec event also carries the " +
			"audit's origin, reach and severity for the image it runs. The process view prefers the kernel's " +
			"proc connector and falls back to the read-only /proc poll when the container refuses the " +
			"subscription; the socket view's default is the sock_diag poll, the source that can name the " +
			"owning process, with conntrack notifications behind --source conntrack.",
		Example: "karma watch proc\nkarma watch socket",
		Args:    cobra.NoArgs,
		RunE:    func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newWatchSocketCmd(), newWatchProcCmd())
	return cmd
}

func newWatchSocketCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "socket",
		Short: "Watch new sockets",
		Long: "Watch new sockets. The default source is the sock_diag poll: it is the source that can name the " +
			"owning process. It prints a socket when its proto, endpoints and inode first appear: a state " +
			"change on the same socket is quiet, while the TIME-WAIT socket the kernel creates after close " +
			"is a new inode and prints. --source conntrack switches to the kernel's flow notifications, which " +
			"see a short TCP or UDP connection a poll can miss; their four-tuple is joined against the " +
			"socket table, so the owner's process still answers where the table knows it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWatch(cmd, watch.FamilySocket)
		},
	}
	watchFlags(cmd, 100*time.Millisecond)
	cmd.Flags().Bool("all", false, "poll: print the baseline and include listeners; conntrack has no baseline")
	return cmd
}

func newWatchProcCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proc",
		Short: "Watch process starts and exits",
		Long: "Watch process starts and exits. The default source is the kernel's proc connector: an event is " +
			"pushed at fork, exec and exit, so a process shorter than a poll interval is still seen. When " +
			"the kernel or the container refuses the subscription, the /proc poll takes over. The scan is " +
			"keyed by pid and starttime, so a reused pid is a new event, and the full facts (cmdline, exe, " +
			"cwd, uid) are read only for keys the previous scan did not carry. The first poll scan is the " +
			"baseline and is silent unless --all is given. The poll source reports a process start as exec; " +
			"--fork is accepted for the connector source.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWatch(cmd, watch.FamilyProcess)
		},
	}
	watchFlags(cmd, 50*time.Millisecond)
	cmd.Flags().Bool("all", false, "print the poll baseline, or include fork and thread events (connector)")
	cmd.Flags().Bool("fork", false, "include fork events (connector source)")
	return cmd
}

// watchFlags registers the flags both views share.
func watchFlags(cmd *cobra.Command, interval time.Duration) {
	flags := cmd.Flags()
	flags.Duration("interval", interval, "poll interval (>= 10ms)")
	flags.Duration("duration", 0, "how long to watch; 0 runs until Ctrl-C")
	flags.String("source", "auto", "event source: auto|poll|connector|conntrack (perf and ebpf are planned)")
	flags.Bool("json", false, "print one JSON object per event")
}

func runWatch(cmd *cobra.Command, family watch.Family) error {
	interval, _ := cmd.Flags().GetDuration("interval")
	duration, _ := cmd.Flags().GetDuration("duration")
	all, _ := cmd.Flags().GetBool("all")
	fork, _ := cmd.Flags().GetBool("fork")
	backend, _ := cmd.Flags().GetString("source")
	asJSON, _ := cmd.Flags().GetBool("json")
	switch {
	case interval < 10*time.Millisecond:
		return usagef(cmd, "--interval must be >= 10ms")
	case duration < 0:
		return usagef(cmd, "--duration must be >= 0")
	}
	options := watch.Options{
		Interval: interval,
		All:      all,
		Fork:     fork,
		Backend:  backend,
		JSON:     asJSON,
	}
	source, err := watch.Open(family, options)
	if err != nil {
		return failf(ExitEnvironment, "%s", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "watch %s: source=%s interval=%s\n", familyName(family), source.Name(), interval)

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}
	if err := watch.Run(ctx, cmd.OutOrStdout(), source, options); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return failf(ExitEnvironment, "watch %s: %s", familyName(family), err)
	}
	return nil
}

func familyName(family watch.Family) string {
	if family == watch.FamilySocket {
		return "socket"
	}
	return "proc"
}
