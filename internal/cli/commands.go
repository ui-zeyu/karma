// The cobra application wiring: local, ssh, and list hang off the root command;
// mtime is a subcommand of local and ssh.
//
// Error reporting funnels through Main: SilenceErrors only keeps cobra from
// printing by itself, and reportError writes both the message and the usage to
// stderr. Errors come in two shapes — a usage error (unknown command, unknown
// flag, wrong argument count) additionally gets that command's usage block, and
// a coded error carries its own exit code for a run that could not happen. Every
// other failure is a mistake the tool explains to a human and leaves the shell's
// exit status at 0.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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

// exitError is an error with an exit code; Main prints the message.
type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }

// usageError is a usage-level error (unknown command, unknown flag, wrong
// argument count): the message plus that command's usage block.
type usageError struct {
	err error
	cmd *cobra.Command
}

func (e usageError) Error() string { return e.err.Error() }

// failf builds an error with an exit code; Main prints the message.
func failf(code int, format string, args ...any) error {
	return exitError{code: code, err: fmt.Errorf(format, args...)}
}

// usagef builds a usage error; Main appends the usage block.
func usagef(cmd *cobra.Command, format string, args ...any) error {
	return usageError{err: fmt.Errorf(format, args...), cmd: cmd}
}

// reportError prints one failure and returns the exit code: a usage error gets
// the command's usage block appended, a coded error returns its own code, and
// anything else — a mistake the message has already explained — returns 0, so a
// typo never looks like a failed run.
func reportError(w io.Writer, err error) int {
	fmt.Fprintf(w, "karma: %v\n", err)
	var usage usageError
	if errors.As(err, &usage) {
		fmt.Fprint(w, usage.cmd.UsageString())
	}
	var coded exitError
	if errors.As(err, &coded) {
		return coded.code
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
	)
	root.SetHelpCommand(helpCommand(root))
	return root
}

// helpCommand replaces cobra's built-in help: a target that does not live on the
// root goes through rootArgs' hints instead of quietly printing the root command
// help (karma help mtime gives the place it is mounted, karma help zzz errors
// out).
func helpCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "help [command]",
		Short: "Show the usage of any command",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _, err := root.Find(args)
			if err != nil {
				return err
			}
			if len(args) > 0 && target == root {
				return rootArgs(root, args)
			}
			return target.Help()
		},
	}
}

// rootArgs: the root command only knows subcommand names, so an unknown word
// gets close commands and a name mounted elsewhere gets its placement.
func rootArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	name := args[0]
	if hint, ok := nameHints[name]; ok {
		return usagef(cmd, "unknown command %q. %s", name, hint)
	}
	if suggestions := closestName(name, cmd.SuggestionsFor(name)); len(suggestions) > 0 {
		return usagef(cmd, "unknown command %q. Did you mean: %s", name, strings.Join(suggestions, ", "))
	}
	return usagef(cmd, "unknown command %q", name)
}

// closestName keeps only the candidates with the smallest edit distance: a
// one-letter typo such as lst should suggest list, without dragging in the
// farther ssh.
func closestName(name string, candidates []string) []string {
	if len(candidates) == 0 {
		return nil
	}
	distances := lo.Map(candidates, func(candidate string, _ int) int {
		return editDistance(name, candidate)
	})
	best := slices.Min(distances)
	return lo.Filter(candidates, func(_ string, index int) bool {
		return distances[index] == best
	})
}

// nameHints: names that are this tool's own subcommands but hang below another
// command, with how to write them.
var nameHints = map[string]string{
	"mtime": `mtime lives under local and ssh: "karma local mtime DIR..." or "karma ssh TARGET mtime DIR..."`,
}

// flagErrorText turns pflag's flag errors into short sentences; an unfamiliar
// shape keeps its original text.
func flagErrorText(err error) string {
	var (
		notExist *pflag.NotExistError
		required *pflag.ValueRequiredError
		invalid  *pflag.InvalidValueError
		syntax   *pflag.InvalidSyntaxError
	)
	switch {
	case errors.As(err, &notExist):
		if shorts := notExist.GetSpecifiedShortnames(); shorts != "" {
			return "unknown shorthand flag -" + notExist.GetSpecifiedName()
		}
		return "unknown flag --" + notExist.GetSpecifiedName()
	case errors.As(err, &required):
		if shorts := required.GetSpecifiedShortnames(); shorts != "" {
			return "flag -" + required.GetSpecifiedName() + " needs a value"
		}
		return "flag --" + required.GetSpecifiedName() + " needs a value"
	case errors.As(err, &invalid):
		return "invalid value " + invalid.GetValue() + " for flag --" + invalid.GetFlag().Name
	case errors.As(err, &syntax):
		return "bad flag syntax: " + syntax.GetSpecifiedFlag()
	}
	return err.Error()
}

// addRunFlags registers the run options shared by local and ssh (long options,
// no shorthands).
func addRunFlags(cmd *cobra.Command) { runFlags(cmd.Flags()) }

// runFlags registers the run options on a plain FlagSet, so assembly and tests
// share one list.
func runFlags(flags *pflag.FlagSet) {
	flags.Int("concurrency", model.DefaultConcurrency, "number of checks to run in parallel")
	flags.Float64("timeout", model.DefaultTimeout.Seconds(), "default timeout per command in seconds")
	flags.Int("max-lines", model.DefaultMaxLines, "maximum number of lines shown per check")
	flags.String("save", "", "write each check's raw text to <dir>/<aspect>/<id>.txt")
}

// runOptions gathers the run options from the command line; selectorArgs are the
// selector words (without the subcommand's target). The flags are registered
// statically by runFlags, so reading them cannot fail and validation only covers
// value ranges.
func runOptions(flags *pflag.FlagSet, selectorArgs []string) (model.RunOptions, error) {
	concurrency := intFlag(flags, "concurrency")
	seconds := floatFlag(flags, "timeout")
	maxLines := intFlag(flags, "max-lines")
	switch {
	case concurrency < 1:
		return model.RunOptions{}, fmt.Errorf("--concurrency must be >= 1")
	case seconds < 0.5:
		return model.RunOptions{}, fmt.Errorf("--timeout must be >= 0.5s")
	case maxLines < 1:
		return model.RunOptions{}, fmt.Errorf("--max-lines must be >= 1")
	}
	return model.RunOptions{
		Selectors:   selectorArgs,
		Concurrency: concurrency,
		Timeout:     time.Duration(seconds * float64(time.Second)),
		MaxLines:    maxLines,
		SaveDir:     stringFlag(flags, "save"),
	}, nil
}

// intFlag / floatFlag / stringFlag / stringSliceFlag read flags directly:
// statically registered flags cannot fail to read, so an error branch would only
// be noise.
func intFlag(flags *pflag.FlagSet, name string) int {
	value, _ := flags.GetInt(name)
	return value
}

func floatFlag(flags *pflag.FlagSet, name string) float64 {
	value, _ := flags.GetFloat64(name)
	return value
}

func stringFlag(flags *pflag.FlagSet, name string) string {
	value, _ := flags.GetString(name)
	return value
}

func stringSliceFlag(flags *pflag.FlagSet, name string) []string {
	value, _ := flags.GetStringSlice(name)
	return value
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
		Long:  "Collect read-only evidence from the local host. Positional arguments are aspect names or check ids; all of them run when omitted.",
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

// addSSHFlags registers the transport options: -p/-i/-o/--password. mtime under
// local does not carry them; mtime under ssh shares them with collection.
func addSSHFlags(cmd *cobra.Command) { sshFlags(cmd.Flags()) }

// sshFlags registers the transport options on a plain FlagSet, so assembly and
// tests share one list.
func sshFlags(flags *pflag.FlagSet) {
	flags.IntP("port", "p", 0, "port, overriding the URI's port")
	flags.StringSliceP("identity", "i", nil, "private key path, repeatable; falls back to ssh-agent and the default keys")
	flags.StringSliceP("ssh-option", "o", nil,
		"only -o StrictHostKeyChecking=no|accept-new|yes is supported (default no, accept anything)")
	flags.String("password", "",
		"password authentication; without it karma uses public keys only and exits when authentication fails")
}

// buildSSHTransport does destination parsing, connection-parameter validation,
// and transport construction in one pass.
func buildSSHTransport(flags *pflag.FlagSet, target string) (session.Transport, error) {
	port := intFlag(flags, "port")
	if port < 0 || port > session.MaxPort {
		return nil, fmt.Errorf("port out of range 1-%d", session.MaxPort)
	}
	identities := stringSliceFlag(flags, "identity")
	for _, path := range identities {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			return nil, fmt.Errorf("identity file not found: %s", path)
		}
	}
	rawOptions := stringSliceFlag(flags, "ssh-option")
	mode := session.HostKeyNo
	seen := false
	for _, raw := range rawOptions {
		key, value, found := strings.Cut(raw, "=")
		if !strings.EqualFold(key, "StrictHostKeyChecking") || !found {
			return nil, fmt.Errorf("only -o StrictHostKeyChecking=no|accept-new|yes is supported (got: %s)", raw)
		}
		if seen {
			return nil, fmt.Errorf("-o StrictHostKeyChecking given twice: %s", raw)
		}
		parsed, err := session.ParseHostKeyMode(strings.ToLower(value))
		if err != nil {
			return nil, err
		}
		mode = parsed
		seen = true
	}
	destination, err := session.ParseSSHDestination(target)
	if err != nil {
		return nil, err
	}
	return &session.SshTransport{
		Destination: destination,
		Port:        port,
		Identities:  identities,
		HostKey:     mode,
		Password:    stringFlag(flags, "password"),
	}, nil
}

func newMtimeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mtime DIR...",
		Short: "Cluster change times for the given directories",
		Long: "Cluster change times for the given directories: deployments and installs form big clusters, " +
			"while a dropped trojan stands out as isolated files. Under local it reads this host; over SSH " +
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

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [selector...]",
		Short: "List the check catalog",
		Long:  "List the check catalog of both platforms, told apart by the platform column; positional arguments are aspect names or check ids; all of them are listed when omitted.",
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
