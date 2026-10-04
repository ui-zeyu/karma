// Help routing: cobra's own help output, plus the two cases where a word does
// not name a command of the root — a name mounted elsewhere, and a typo. Help
// and usage blocks render in the report's visual language via the render
// package's Band and Panel: the command as a level-one band, each section as a
// quiet rail panel.

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"karma/internal/render"
)

// styledHelp renders one command's help: the command band, the long
// description, then the section panels. Writing straight to the command's
// output stream keeps profile detection on the real stream — cobra's
// UsageString would route the block through a capture buffer, which always
// looks like a pipe.
func styledHelp(cmd *cobra.Command) {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, render.Band(cmd.CommandPath(), terminalWidth(w)))
	if long := cmd.Long; long != "" {
		fmt.Fprintf(w, "%s\n\n", strings.TrimRight(long, "\n"))
	} else if cmd.Short != "" {
		fmt.Fprintf(w, "%s\n\n", cmd.Short)
	}
	styledUsageWith(w, cmd, stylesFor(w))
}

// styledUsage renders the usage block at the stream's own styles.
func styledUsage(w io.Writer, cmd *cobra.Command) {
	styledUsageWith(w, cmd, stylesFor(w))
}

// styledUsageWith renders the usage block in the report's visual language: a
// USAGE panel, a COMMANDS panel for the subcommands, FLAGS panels for the flag
// tables, with bold names and muted descriptions. Tests use it with a forced
// style set on a capture buffer.
func styledUsageWith(w io.Writer, cmd *cobra.Command, st streamStyles) {
	width := terminalWidth(w)
	path := cmd.CommandPath()
	var pieces []string
	if cmd.Runnable() || cmd.HasAvailableSubCommands() {
		var rows []string
		if cmd.Runnable() {
			rows = append(rows, useLineStyled(path, cmd.UseLine(), st))
		}
		if cmd.HasAvailableSubCommands() {
			rows = append(rows, useLineStyled(path, path+" [command]", st))
		}
		pieces = append(pieces, render.Panel("usage", rows, width))
	}
	if cmd.HasAvailableSubCommands() {
		var rows []string
		for _, sub := range cmd.Commands() {
			// cobra's own template special-cases the help command the same way
			if !sub.IsAvailableCommand() && sub.Name() != "help" {
				continue
			}
			rows = append(rows, st.bold(rpad(sub.Name(), cmd.NamePadding()))+st.muted("  "+sub.Short))
		}
		pieces = append(pieces, render.Panel("commands", rows, width))
	}
	if local := cmd.LocalFlags().FlagUsages(); local != "" {
		pieces = append(pieces, render.Panel("flags", flagRows(st, local), width))
	}
	if inherited := cmd.InheritedFlags().FlagUsages(); inherited != "" {
		pieces = append(pieces, render.Panel("global flags", flagRows(st, inherited), width))
	}
	if len(pieces) > 0 {
		fmt.Fprintln(w, strings.Join(pieces, "\n\n"))
	}
	if cmd.HasAvailableSubCommands() {
		fmt.Fprintf(w, "\n%s\n",
			st.muted(`Use "`+path+` [command] --help" for more information about a command.`))
	}
}

// useLineStyled bolds the command path and mutes the placeholders and flags.
func useLineStyled(path, use string, st streamStyles) string {
	rest, ok := strings.CutPrefix(use, path)
	if !ok || rest == "" {
		return use
	}
	return st.bold(path) + st.muted(rest)
}

// flagRows styles cobra's flag usage block row by row: the flag names before
// the double-space gap go bold, the description and any continuation line go
// muted; the panel body provides the indent.
func flagRows(st streamStyles, block string) []string {
	lines := strings.Split(strings.TrimRight(block, "\n"), "\n")
	rows := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		if !strings.HasPrefix(trimmed, "-") {
			rows = append(rows, st.muted(line))
			continue
		}
		if gap := strings.Index(trimmed, "  "); gap > 0 {
			rows = append(rows, st.bold(trimmed[:gap])+st.muted(trimmed[gap:]))
			continue
		}
		rows = append(rows, line)
	}
	return rows
}

// rpad pads on the right, matching cobra's own template helper.
func rpad(s string, padding int) string {
	return fmt.Sprintf("%-*s", padding, s)
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

// nameHints: names that are this tool's own subcommands but hang below another
// command, with how to write them.
var nameHints = map[string]string{
	"mtime": `mtime lives under local and ssh: "karma local mtime DIR..." or "karma ssh TARGET mtime DIR..."`,
}
