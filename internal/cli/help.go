// Help routing: cobra's own help output, plus the two cases where a word does
// not name a command of the root — a name mounted elsewhere, and a typo.

package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

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

// nameHints: names that are this tool's own subcommands but hang below another
// command, with how to write them.
var nameHints = map[string]string{
	"mtime": `mtime lives under local and ssh: "karma local mtime DIR..." or "karma ssh TARGET mtime DIR..."`,
}
