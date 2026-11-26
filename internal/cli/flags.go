// Flag registration and reading: the audit options.

package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"karma/internal/audit"
)

func addRunFlags(cmd *cobra.Command) { runFlags(cmd.Flags()) }

func runFlags(flags *pflag.FlagSet) {
	flags.Bool("json", false, "print the report as one JSON object")
	flags.Bool("evidence", false, "print the raw inventories after the findings")
	flags.String("min-severity", "all", "report findings at or above this severity: all|info|low|medium|high|critical")
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
	if word := stringFlag(flags, "min-severity"); word != "all" {
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
