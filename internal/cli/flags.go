// Flag registration and reading: the run options shared by local and ssh, the
// SSH transport options, and the conversion from flags to run options.
//
// Registration goes through plain FlagSets (runFlags/sshFlags) so assembly and
// tests share one list; reading is direct (intFlag and friends) because a
// statically registered flag cannot fail to read, and validation only covers
// value ranges.

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"karma/internal/model"
	"karma/internal/session"
)

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
// selector words (without the subcommand's target).
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

func boolFlag(flags *pflag.FlagSet, name string) bool {
	value, _ := flags.GetBool(name)
	return value
}

func stringSliceFlag(flags *pflag.FlagSet, name string) []string {
	value, _ := flags.GetStringSlice(name)
	return value
}

// addSSHFlags registers the transport options: -p/-i/-o/--password. mtime under
// local does not carry them; mtime under ssh shares them with collection.
func addSSHFlags(cmd *cobra.Command) { sshFlags(cmd.Flags()) }

// sshFlags registers the transport options on a plain FlagSet, so assembly and
// tests share one list.
func sshFlags(flags *pflag.FlagSet) {
	flags.IntP("port", "p", 0, "port, overriding the URI's port")
	flags.StringSliceP("identity", "i", nil,
		"private key path, repeatable; without it the default ~/.ssh keys are tried (ssh-agent signers are always offered)")
	flags.StringSliceP("ssh-option", "o", nil,
		"only -o StrictHostKeyChecking=no|accept-new|yes is supported (default no, accept anything); "+
			"accept-new accepts a new host without recording it")
	flags.String("password", "",
		"password authentication, and the passphrase of an encrypted private key; "+
			"without it karma uses public keys only and exits when authentication fails")
}

// addTTYDFlags registers the ttyd transport options: the credential for ttyd's
// basic authentication and the TLS answers for wss.
func addTTYDFlags(cmd *cobra.Command) { ttydFlags(cmd.Flags()) }

func ttydFlags(flags *pflag.FlagSet) {
	flags.String("credential", "",
		"user:pass for ttyd's basic authentication, sent on the upgrade and in the handshake; "+
			"the user:pass@host spelling in the target sets it too")
	flags.Bool("insecure", false, "wss: accept any server certificate")
	flags.String("tls-pin", "",
		"wss: the server certificate's SHA-256 fingerprint as 64 hex characters, verified instead of the chain")
}

// addBootstrapFlags registers the bootstrap mode's own option: it is accepted
// on both channels and unused outside that mode.
func addBootstrapFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("keep", false,
		"bootstrap: leave the uploaded binary on the target instead of removing it")
}

// buildTTYDTransport reads the ttyd flags into the transport; the endpoint
// itself is parsed when the connection opens.
func buildTTYDTransport(flags *pflag.FlagSet, target string) (session.Transport, error) {
	return &session.TTYDTransport{
		Target:     target,
		Credential: stringFlag(flags, "credential"),
		Insecure:   boolFlag(flags, "insecure"),
		Pin:        stringFlag(flags, "tls-pin"),
	}, nil
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
		info, err := os.Stat(path)
		switch {
		case err != nil && errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("identity file not found: %s", path)
		case err != nil:
			return nil, fmt.Errorf("cannot access identity file %s: %v", path, err)
		case info.IsDir():
			return nil, fmt.Errorf("identity file is a directory: %s", path)
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
	return &session.SSHTransport{
		Destination: destination,
		Port:        port,
		Identities:  identities,
		HostKey:     mode,
		Password:    stringFlag(flags, "password"),
	}, nil
}
