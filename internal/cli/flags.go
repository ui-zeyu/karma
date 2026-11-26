// Flag registration and reading: the audit options.

package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"karma/internal/audit"
)

// addRunFlags registers the audit's option set on the bare run and on
// `karma audit`.
func addRunFlags(cmd *cobra.Command) { runFlags(cmd.Flags()) }

// runFlags is the full option set. The graph and show commands register the
// subset they answer to, so a command's page promises only what it does.
func runFlags(flags *pflag.FlagSet) {
	flags.Bool("json", false, "print the report as one JSON object")
	flags.Bool("evidence", false, "print the raw inventories after the findings")
	flags.String("min-severity", "all", "report findings at or above this severity: all|info|low|medium|high|critical")
	flags.String("since", "provision",
		"artifact boundary: provision|boot|auto, a duration such as 24h, or an RFC3339 time")
	flags.Duration("timeout", 120*time.Second, "budget of the whole collection in seconds")
}

// graphFlags is the option set a relation graph answers to.
func graphFlags(flags *pflag.FlagSet) {
	flags.Bool("json", false, "print the graph as one JSON object")
	flags.String("min-severity", "all", "report findings at or above this severity: all|info|low|medium|high|critical")
	flags.String("since", "provision",
		"artifact boundary: provision|boot|auto, a duration such as 24h, or an RFC3339 time")
	flags.Duration("timeout", 120*time.Second, "budget of the whole collection in seconds")
}

// showFlags is the option set a raw inventory answers to.
func showFlags(flags *pflag.FlagSet) {
	flags.Bool("json", false, "print the section's collected structures as one JSON object")
	flags.String("since", "provision",
		"artifact boundary: provision|boot|auto, a duration such as 24h, or an RFC3339 time")
	flags.Duration("timeout", 120*time.Second, "budget of the whole collection in seconds")
}

func auditOptions(flags *pflag.FlagSet) (auditFlags, error) {
	budget := durationFlag(flags, "timeout")
	if budget < time.Second {
		return auditFlags{}, fmt.Errorf("--timeout must be at least 1s")
	}
	floor := audit.Info
	if word := stringFlag(flags, "min-severity"); word != "" && word != "all" {
		parsed, ok := audit.ParseSeverity(word)
		if !ok {
			return auditFlags{}, fmt.Errorf("--min-severity must be all|info|low|medium|high|critical")
		}
		floor = parsed
	}
	return auditFlags{
		json:        boolFlag(flags, "json"),
		evidence:    boolFlag(flags, "evidence"),
		minSeverity: floor,
		since:       stringFlag(flags, "since"),
		timeout:     budget,
	}, nil
}

func durationFlag(flags *pflag.FlagSet, name string) time.Duration {
	if flags.Lookup(name) == nil {
		return 120 * time.Second
	}
	value, _ := flags.GetDuration(name)
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
