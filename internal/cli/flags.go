// Flag registration and reading: the audit options shared by every channel and
// the transport options for ssh and ttyd.

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

	"karma/internal/audit"
	"karma/internal/session"
)

func addRunFlags(cmd *cobra.Command) { runFlags(cmd.Flags()) }

func runFlags(flags *pflag.FlagSet) {
	flags.Bool("json", false, "print the report as one JSON object")
	flags.Bool("no-evidence", false, "hide the raw inventories printed after the findings")
	flags.String("min-severity", "all", "report findings at or above this severity: all|info|low|medium|high|critical")
	flags.String("since", "provision",
		"artifact boundary: provision|boot|auto, a duration such as 24h, or an RFC3339 time")
	flags.Float64("timeout", 60, "budget of the whole collection in seconds")
}

func auditOptions(flags *pflag.FlagSet) (auditFlags, error) {
	seconds := floatFlag(flags, "timeout")
	if seconds < 1 {
		return auditFlags{}, fmt.Errorf("--timeout must be >= 1s")
	}
	floor := audit.Info
	if word := stringFlag(flags, "min-severity"); word != "all" {
		parsed, ok := audit.ParseSeverity(word)
		if !ok {
			return auditFlags{}, fmt.Errorf("--min-severity must be all|info|low|medium|high|critical")
		}
		floor = parsed
	}
	return auditFlags{
		json:        boolFlag(flags, "json"),
		evidence:    !boolFlag(flags, "no-evidence"),
		minSeverity: floor,
		since:       stringFlag(flags, "since"),
		timeout:     time.Duration(seconds * float64(time.Second)),
	}, nil
}

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

func addSSHFlags(cmd *cobra.Command) { sshFlags(cmd.Flags()) }

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

func addTTYDFlags(cmd *cobra.Command) { ttydFlags(cmd.Flags()) }

func ttydFlags(flags *pflag.FlagSet) {
	flags.String("credential", "",
		"user:pass for ttyd's basic authentication, sent on the upgrade and in the handshake; "+
			"the user:pass@host spelling in the target sets it too")
	flags.Bool("insecure", false, "wss: accept any server certificate")
	flags.String("tls-pin", "",
		"wss: the server certificate's SHA-256 fingerprint as 64 hex characters, verified instead of the chain")
}

func buildTTYDTransport(flags *pflag.FlagSet, target string) (session.Transport, error) {
	return &session.TTYDTransport{
		Target:     target,
		Credential: stringFlag(flags, "credential"),
		Insecure:   boolFlag(flags, "insecure"),
		Pin:        stringFlag(flags, "tls-pin"),
	}, nil
}

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
		case !info.Mode().IsRegular():
			return nil, fmt.Errorf("identity file is not a regular file: %s", path)
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
