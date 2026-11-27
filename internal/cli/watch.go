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
			return runWatch(cmd)
		},
	}
	watchFlags(cmd, watch.DefaultInterval(watch.FamilySocket))
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
			return runWatch(cmd)
		},
	}
	watchFlags(cmd, watch.DefaultInterval(watch.FamilyProcess))
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

// watchOptions is the one read of the watch flags: the cadence, the stop
// time, the family the command watches, and the options the source and the
// runner take. The family follows the command that opened the view.
func watchOptions(cmd *cobra.Command) (duration time.Duration, family watch.Family, opt watch.Options, run watch.RunOptions, err error) {
	family = watch.FamilyProcess
	if cmd.Name() == "socket" {
		family = watch.FamilySocket
	}
	flags := cmd.Flags()
	opt.Interval, _ = flags.GetDuration("interval")
	duration, _ = flags.GetDuration("duration")
	opt.All = boolFlag(flags, "all")
	opt.Fork = boolFlag(flags, "fork")
	opt.Backend = stringFlag(flags, "source")
	run = watch.RunOptions{JSON: boolFlag(flags, "json")}
	switch {
	case opt.Interval < 10*time.Millisecond:
		return 0, family, opt, run, usagef(cmd, "--interval must be >= 10ms")
	case duration < 0:
		return 0, family, opt, run, usagef(cmd, "--duration must be >= 0")
	}
	return duration, family, opt, run, nil
}

func runWatch(cmd *cobra.Command) error {
	duration, family, options, run, err := watchOptions(cmd)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	// Opening a source is one bounded setup: a netlink dial, a subscription
	// and a baseline scan. A kernel that stalls any of them must not park the
	// command before the stream starts.
	openCtx, cancelOpen := context.WithTimeout(ctx, 10*time.Second)
	source, err := watch.Open(openCtx, family, options)
	cancelOpen()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return failf(ExitEnvironment, "watch %s: opening the source exceeded 10s", family)
		}
		return failf(ExitEnvironment, "%s", err)
	}
	if source.Caps().Push {
		// The kernel-push backends do not poll; the cadence is not theirs to print.
		fmt.Fprintf(cmd.ErrOrStderr(), "watch %s: source=%s interval n/a\n", family, source.Name())
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "watch %s: source=%s interval=%s\n", family, source.Name(), options.Interval)
	}

	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}
	if err := watch.Run(ctx, cmd.OutOrStdout(), source, run); err != nil {
		// A duration expiry and a Ctrl-C are different answers for a script:
		// the expiry is the run the caller asked for (0), an interrupt is
		// 130, the same code audit and ctime report.
		if errors.Is(err, context.Canceled) {
			return failf(ExitInterrupted, "watch %s: interrupted", family)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return failf(ExitEnvironment, "watch %s: %s", family, err)
	}
	return nil
}
