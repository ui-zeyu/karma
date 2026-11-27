// Flag registration and reading: the audit options.

package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// collectionTimeout is the one default budget of a collecting run.
const collectionTimeout = 120 * time.Second

// addRunFlags registers the audit's option set on the bare run and on
// `karma audit`.
func addRunFlags(cmd *cobra.Command) { runFlags(cmd.Flags()) }

// collectionFlags registers the options every collecting command shares: the
// artifact boundary and the time budget. The graph and show commands register
// the subset they answer to, so a command's page promises only what it does.
func collectionFlags(flags *pflag.FlagSet) {
	flags.String("since", "provision",
		"artifact boundary: provision|boot, a duration such as 24h, or an RFC3339 time")
	flags.Duration("timeout", collectionTimeout, "budget of the whole collection, a duration such as 45s or 2m")
}

// runFlags is the full option set.
func runFlags(flags *pflag.FlagSet) {
	collectionFlags(flags)
	flags.Bool("json", false, "print the report as one JSON object")
	flags.Bool("evidence", false, "print the raw inventories after the findings")
}

// graphFlags is the option set a relation graph answers to.
func graphFlags(flags *pflag.FlagSet) {
	collectionFlags(flags)
	flags.Bool("json", false, "print the graph as one JSON object")
}

// showFlags is the option set a raw inventory answers to.
func showFlags(flags *pflag.FlagSet) {
	collectionFlags(flags)
	flags.Bool("json", false, "print the section's collected structures as one JSON object")
}

func auditOptions(flags *pflag.FlagSet) (auditFlags, error) {
	budget := durationFlag(flags, "timeout")
	if budget < time.Second {
		return auditFlags{}, fmt.Errorf("--timeout must be at least 1s")
	}
	since, err := parseSince(stringFlag(flags, "since"))
	if err != nil {
		return auditFlags{}, err
	}
	return auditFlags{
		json:     boolFlag(flags, "json"),
		evidence: boolFlag(flags, "evidence"),
		since:    since,
		timeout:  budget,
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
