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
