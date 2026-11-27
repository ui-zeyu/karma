package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	chrome "karma/internal/panel"
)

// helpTree is a small command tree shaped like the real one.
func helpTree(buf *bytes.Buffer) *cobra.Command {
	root := &cobra.Command{
		Use:     "karma [scope...]",
		Short:   "short",
		Long:    "Read-only collection over every bounded domain.",
		Version: "9.9.9",
		RunE:    func(*cobra.Command, []string) error { return nil },
	}
	root.Flags().Bool("json", false, "print the report as one JSON object")
	root.SetOut(buf)
	root.AddCommand(&cobra.Command{
		Use:     "audit [scope...]",
		Short:   "Audit the local host",
		Example: "karma audit persistence",
		RunE:    func(*cobra.Command, []string) error { return nil },
	})
	return root
}

// startTree adds the commands the entry guide names, so the derived START
// panel has spellings to draw.
func startTree(buf *bytes.Buffer) *cobra.Command {
	root := helpTree(buf)
	for _, sub := range []*cobra.Command{
		{Use: "graph <domain|object>", Short: "Print one relation graph", RunE: func(*cobra.Command, []string) error { return nil }},
		{Use: "show <section> [scope...]", Short: "Print one collected inventory without judging it", RunE: func(*cobra.Command, []string) error { return nil }},
		{Use: "watch", Short: "Watch live process and socket events", RunE: func(*cobra.Command, []string) error { return nil }},
	} {
		root.AddCommand(sub)
	}
	return root
}

// TestRootHelpWearsTheReportPanels pins the help screen's shape: the level-one
// band with the command path and byline, the version head over the
// description, and the usage/commands/flags rail panels.
func TestRootHelpWearsTheReportPanels(t *testing.T) {
	t.Setenv("USER", "yuyy")
	var buf bytes.Buffer
	root := startTree(&buf)
	rootHelp(root)
	root.InitDefaultHelpFlag()
	if err := root.Help(); err != nil {
		t.Fatalf("help: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"KARMA", "yuyy", "9.9.9", "Read-only collection over every bounded domain.",
		"▌ START", "karma graph <domain|object>", "one domain or object as relations",
		"karma show <section> [scope...]", "one raw inventory, unjudged", "karma watch", "live events",
		"▌ SCOPE", "domain      services processes", "exclusion   !network",
		"▌ USAGE", "karma [scope...] [flags]", "▌ COMMANDS", "▌ FLAGS",
		"audit", "Audit the local host", "-h, --help", "--json",
		`Use "karma [command] --help" for more information about a command.`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("a capture buffer must render without ANSI:\n%s", out)
	}
}

// TestHelpFuncReachesSubcommands pins that a subcommand wears the same chrome:
// cobra hands the root's help function down.
func TestHelpFuncReachesSubcommands(t *testing.T) {
	var buf bytes.Buffer
	root := helpTree(&buf)
	rootHelp(root)
	sub, _, err := root.Find([]string{"audit"})
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if err := sub.Help(); err != nil {
		t.Fatalf("sub help: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"KARMA AUDIT", "9.9.9", "Audit the local host", "▌ SCOPE", "▌ EXAMPLES", "karma audit persistence"} {
		if !strings.Contains(out, want) {
			t.Errorf("subcommand help lacks %q:\n%s", want, out)
		}
	}
}

// TestHelpFlagsKeepTheAlignedColumn pins the flag table: pflag's description
// column survives the styling, and a description wider than the panel wraps
// between words under a hanging indent instead of being hard-cut.
func TestHelpFlagsKeepTheAlignedColumn(t *testing.T) {
	plain := func(s string) string { return s }
	block := "  -h, --help   help for karma\n" +
		"      --json   print the report as one JSON object"
	rows := flagRows(block, 60, plain, plain)
	if len(rows) != 2 {
		t.Fatalf("rows = %v", rows)
	}
	for index, desc := range []string{"help for karma", "print the report"} {
		if at := strings.Index(rows[index], desc); at != 15 {
			t.Fatalf("row %q puts its description at %d, want 15", rows[index], at)
		}
	}

	var buf bytes.Buffer
	root := &cobra.Command{Use: "karma", Short: "short", Version: "9.9.9"}
	root.SetOut(&buf)
	root.Flags().String("alpha", "", "print every activation surface, process, socket, authority object and mount in scope (default \"all\")")
	rootHelp(root)
	root.InitDefaultHelpFlag()
	if err := root.Help(); err != nil {
		t.Fatalf("help: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "mount") {
		t.Fatalf("the wrapped description lost a word:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if width := chrome.DisplayWidth(line); width > terminalWidth(&buf) {
			t.Errorf("line %d columns wide, over the terminal: %q", width, line)
		}
	}
}

// TestListPageWearsThePanels pins the vocabulary listing as a command page:
// the masthead, the six word-family panels, and the footer, all built from
// the registries.
func TestListPageWearsThePanels(t *testing.T) {
	var buf bytes.Buffer
	root := helpTree(&buf)
	for _, name := range []string{"graph", "show", "cat", "ls", "ctime", "watch"} {
		root.AddCommand(&cobra.Command{
			Use:  name,
			RunE: func(*cobra.Command, []string) error { return nil },
		})
	}
	root.AddCommand(newListCmd())
	list, _, err := root.Find([]string{"list"})
	if err != nil {
		t.Fatalf("find list: %v", err)
	}
	if err := list.RunE(list, nil); err != nil {
		t.Fatalf("list: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"KARMA LIST", "9.9.9", "List the audit vocabulary",
		"▌ START", "audit the whole host",
		"▌ MODES", "▌ DOMAINS", "▌ GRAPH", "▌ SHOW", "▌ SURFACES", "▌ GROUPS",
		"audit (default) audit cat ctime graph list ls show watch",
		"services processes", "Use a word with any command",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("list page lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("a capture buffer must render without ANSI:\n%s", out)
	}
}

// TestBareShowOpensThePage pins that a subcommand that needs an argument
// presents its own page instead of a bare list of words.
func TestBareShowIsAUsageError(t *testing.T) {
	var buf bytes.Buffer
	root := helpTree(&buf)
	root.AddCommand(newShowCmd())
	rootHelp(root)
	show, _, err := root.Find([]string{"show"})
	if err != nil {
		t.Fatalf("find show: %v", err)
	}
	// A bare show is a usage mistake like a bare cat or ctime: the page
	// stays on `karma help show`, the exit code answers 2.
	err = show.RunE(show, nil)
	var usage usageError
	if err == nil || !errors.As(err, &usage) {
		t.Fatalf("bare show = %v, want a usage error", err)
	}
	writePage(&buf, show, helpSections(show, 80, false), helpFooter(show))
	out := buf.String()
	for _, want := range []string{"KARMA SHOW", "▌ SCOPE", "▌ USAGE", "▌ EXAMPLES"} {
		if !strings.Contains(out, want) {
			t.Errorf("show page lacks %q:\n%s", want, out)
		}
	}
}

// TestRetiredProfileWordHintsAtGraph pins the merge guard: the old command
// name at the root states its new home instead of silently becoming a scope
// word (profile is also a startup surface).
func TestRetiredProfileWordHintsAtGraph(t *testing.T) {
	err := retiredWord("profile")
	if err == nil || !strings.Contains(err.Error(), "karma graph") {
		t.Fatalf("retiredWord(profile) = %v, want a graph hint", err)
	}
	if err := retiredWord("systemd"); err != nil {
		t.Fatalf("retiredWord(systemd) = %v, want nil", err)
	}
}

// TestUsageErrorWearsThePanels pins the error path: a usage failure prints
// its message and the page-language usage panels, never cobra's plain block.
func TestUsageErrorWearsThePanels(t *testing.T) {
	var buf bytes.Buffer
	root := helpTree(&buf)
	rootHelp(root)
	code := reportError(&buf, usagef(root, "boom"))
	if code != int(ExitEnvironment) {
		t.Fatalf("exit = %d, want %d", code, ExitEnvironment)
	}
	out := buf.String()
	for _, want := range []string{"karma: boom", "▌ USAGE", "▌ COMMANDS", "▌ FLAGS"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage error lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\nUsage:\n") {
		t.Errorf("the default cobra block leaked:\n%s", out)
	}
}
