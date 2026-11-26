// The command pages: help screens and the vocabulary listing are drawn in the
// report's own language — the command path as the level-one band with the
// byline on its right edge, the build's version as the level-two head over the
// command's description, then quiet rail panels, then a muted footer.

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"karma/internal/audit"
	chrome "karma/internal/panel"
)

// pageSection is one panel of a command page: the title and its rows.
type pageSection struct {
	title string
	rows  []string
}

// startRows is the entry guide shared by the root help and the vocabulary
// page: the command on the left, the question it answers on the right.
var startRows = []string{
	startRow("karma", "audit the whole host"),
	startRow("karma <domain|path>", "audit one slice of it"),
	startRow("karma graph <word>", "one domain or object as relations"),
	startRow("karma show <section>", "one raw inventory, unjudged"),
	startRow("karma watch proc|socket", "live events"),
}

// startRow lines one start-table entry up in the command column.
func startRow(command, answer string) string { return column(26, command, answer) }

// column lines one entry up in a fixed left column.
func column(width int, left, right string) string {
	return fmt.Sprintf("%-*s%s", width, left, right)
}

// scopeRows is the narrowing vocabulary the audit-shaped commands accept,
// with every word list read from the registry that defines it. A long word
// list wraps at the body width with a hanging indent, so the rail never
// hard-cuts a word inside the aligned row.
func scopeRows(body int) []string {
	var rows []string
	for _, entry := range []struct{ label, text string }{
		{"domain", strings.Join(audit.DomainWords(), " ")},
		{"surface", strings.Join(surfaceWords, " ")},
		{"group", strings.Join(groupWords(), " ")},
		{"path", "/var/www  a path prefix"},
		{"pid", "/proc/36  that process's slice"},
		{"unit", "ssh.service"},
		{"exclusion", "!network  drop a word"},
	} {
		wrapped := chrome.Wrap(entry.text, body-12)
		rows = append(rows, column(12, entry.label, wrapped[0]))
		for _, cont := range wrapped[1:] {
			rows = append(rows, strings.Repeat(" ", 12)+cont)
		}
	}
	return rows
}

// rootHelp installs the styled help on the root; cobra hands it down to every
// subcommand that has no help function of its own.
func rootHelp(root *cobra.Command) {
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) { styledHelp(cmd) })
}

func helpCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "help [command]",
		Short: "Show the usage of any command",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _, err := root.Find(args)
			if err != nil {
				return usagef(cmd, "%s", err)
			}
			return target.Help()
		},
	}
}

// styledHelp renders one command's screens: the masthead, then the section
// panels. Writing straight to the command's output stream keeps profile
// detection on the real stream.
func styledHelp(cmd *cobra.Command) {
	w := cmd.OutOrStdout()
	writePage(w, cmd, helpSections(cmd, terminalWidth(w), isTerminal(w)), helpFooter(cmd))
}

// writeUsage prints a usage error's guide in the command pages' language: the
// usage, command list and flag panels, without the masthead.
func writeUsage(w io.Writer, cmd *cobra.Command) {
	width := terminalWidth(w)
	color := isTerminal(w)
	printed := false
	for _, section := range helpSections(cmd, width, color) {
		switch section.title {
		case "usage", "commands", "flags", "global flags":
		default:
			continue
		}
		if printed {
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, sectionPanel(section.title, section.rows, width, color))
		printed = true
	}
}

// writePage draws one command page: the masthead, one quiet panel per section,
// and the muted footer.
func writePage(w io.Writer, cmd *cobra.Command, sections []pageSection, footer string) {
	width := terminalWidth(w)
	color := isTerminal(w)
	fmt.Fprintln(w, pageMasthead(cmd, width, color))
	for _, section := range sections {
		fmt.Fprintln(w)
		fmt.Fprintln(w, sectionPanel(section.title, section.rows, width, color))
	}
	if footer != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, chrome.Paint(color, chrome.Fg(chrome.MutedColor), footer))
	}
}

// pageMasthead is the report's first panel: the command path as the level-one
// band, the version as the level-two head, the description inside the rail.
func pageMasthead(cmd *cobra.Command, width int, color bool) string {
	version := cmd.Root().Version
	if version == "" {
		version = "dev"
	}
	band := chrome.Band(" "+strings.ToUpper(cmd.CommandPath()), "yuyy ", width,
		chrome.BannerBG, chrome.BannerFG, true, color)
	head := chrome.Band(" "+version, "", width-2, chrome.SubBandBG, chrome.SubBandFG, false, color)
	return band + "\n" + chrome.Rail(head, descriptionRows(cmd), width, chrome.MutedColor, color)
}

// descriptionRows is the masthead's body: the command's long description, or
// its one-line short when it carries no long one.
func descriptionRows(cmd *cobra.Command) []string {
	text := strings.TrimRight(cmd.Long, "\n")
	if text == "" {
		text = cmd.Short
	}
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// sectionPanel renders one section as a quiet rail panel.
func sectionPanel(title string, rows []string, width int, color bool) string {
	head := chrome.Band(" "+strings.ToUpper(title), "", width-2,
		chrome.SubBandBG, chrome.SubBandFG, false, color)
	return chrome.Rail(head, rows, width, chrome.MutedColor, color)
}

// helpSections draws usage, commands and flags as quiet rail panels, with bold
// names and muted descriptions.
func helpSections(cmd *cobra.Command, width int, color bool) []pageSection {
	path := cmd.CommandPath()
	bold := func(s string) string { return chrome.Paint(color, "\x1b[1m", s) }
	muted := func(s string) string { return chrome.Paint(color, chrome.Fg(chrome.MutedColor), s) }
	var sections []pageSection
	if cmd.Parent() == nil {
		// The root page leads with the entry guide: which command answers
		// which question.
		sections = append(sections, pageSection{"start", startRows})
	}
	if cmd.Parent() == nil || cmd.Name() == "audit" || cmd.Name() == "show" {
		// The commands that take narrowing words state them here; the full
		// vocabulary page is `karma list`.
		sections = append(sections, pageSection{"scope", scopeRows(width - 4)})
	}
	if cmd.Runnable() || cmd.HasAvailableSubCommands() {
		var rows []string
		if cmd.Runnable() {
			rows = append(rows, useLineStyled(path, cmd.UseLine(), bold, muted))
		}
		if cmd.HasAvailableSubCommands() {
			rows = append(rows, useLineStyled(path, path+" [command]", bold, muted))
		}
		sections = append(sections, pageSection{"usage", rows})
	}
	if rows := exampleRows(cmd.Example); len(rows) > 0 {
		sections = append(sections, pageSection{"examples", rows})
	}
	if cmd.HasAvailableSubCommands() {
		var rows []string
		for _, sub := range cmd.Commands() {
			// cobra's own template special-cases the help command the same way
			if !sub.IsAvailableCommand() && sub.Name() != "help" {
				continue
			}
			rows = append(rows, bold(rpad(sub.Name(), cmd.NamePadding()))+muted("  "+sub.Short))
		}
		sections = append(sections, pageSection{"commands", rows})
	}
	if local := cmd.LocalFlags().FlagUsages(); local != "" {
		sections = append(sections, pageSection{"flags", flagRows(local, width-4, bold, muted)})
	}
	if inherited := cmd.InheritedFlags().FlagUsages(); inherited != "" {
		sections = append(sections, pageSection{"global flags", flagRows(inherited, width-4, bold, muted)})
	}
	return sections
}

// exampleRows splits a command's Example block into panel rows: one command
// per line, the rail providing the indent.
func exampleRows(example string) []string {
	var rows []string
	for _, line := range strings.Split(strings.TrimRight(example, "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			rows = append(rows, line)
		}
	}
	return rows
}

// helpFooter is the hint under a help page that has subcommands.
func helpFooter(cmd *cobra.Command) string {
	if !cmd.HasAvailableSubCommands() {
		return ""
	}
	return `Use "` + cmd.CommandPath() + ` [command] --help" for more information about a command.`
}

// useLineStyled bolds the command path and mutes the placeholders and flags.
func useLineStyled(path, use string, bold, muted func(string) string) string {
	rest, ok := strings.CutPrefix(use, path)
	if !ok || rest == "" {
		return use
	}
	return bold(path) + muted(rest)
}

// flagRows styles cobra's flag usage block row by row: the flag names go bold,
// the descriptions muted, and pflag's own description column stays intact. A
// description that cannot fit the panel is wrapped here to the column's
// remaining width, with continuation lines hanging under the description, so
// the rail never hard-cuts a word inside the aligned line.
func flagRows(block string, body int, bold, muted func(string) string) []string {
	lines := strings.Split(strings.TrimRight(block, "\n"), "\n")
	rows := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		if !strings.HasPrefix(trimmed, "-") {
			rows = append(rows, muted(line))
			continue
		}
		gap := strings.Index(trimmed, "  ")
		if gap <= 0 {
			rows = append(rows, line)
			continue
		}
		desc := strings.TrimLeft(trimmed[gap:], " ")
		column := len(line) - len(desc)
		avail := body - column
		if avail < 20 {
			column = body - 20
			avail = 20
		}
		wrapped := chrome.Wrap(desc, avail)
		rows = append(rows, bold(line[:column])+muted(wrapped[0]))
		for _, cont := range wrapped[1:] {
			rows = append(rows, strings.Repeat(" ", column)+muted(cont))
		}
	}
	return rows
}

// rpad pads on the right, matching cobra's own template helper.
func rpad(s string, padding int) string {
	return fmt.Sprintf("%-*s", padding, s)
}
