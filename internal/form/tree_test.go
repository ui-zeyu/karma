package form

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"karma/internal/model"
)

// processTree is the process tree's declaration: the pid identifies a node, the
// ppid links it to its parent, and the line draws the identity and the command.
var processTree = Tree{ID: "PID", Parent: "PPID", Label: []string{"PID", "COMMAND"}}

// treeBlock is a process tree's records, in whatever order the fixture lists
// them: the form works the nest out of the links.
func treeBlock(items ...model.BlockItem) model.Block {
	return model.Block{Header: []string{"PID", "PPID", "USER", "COMMAND"}, Items: items}
}

func node(pid, ppid, command string) model.BlockItem {
	return model.BlockItem{Rec: row("PID", pid, "PPID", ppid, "USER", "root", "COMMAND", command)}
}

// The nest is the form's: roots stand at the left, children hang from their
// parent with tree's glyphs, and siblings follow their pid whatever order the
// records arrived in.
func TestTreeNestsTheNodes(t *testing.T) {
	lines := processTree.Render(treeBlock(
		node("2210", "948", "-bash"),
		node("1", "0", "/sbin/init"),
		node("948", "1", "/usr/sbin/sshd -D"),
		node("630", "1", "/usr/sbin/accounts-daemon"),
	), model.RenderOptions{Width: 80})
	want := []string{
		"1 /sbin/init",
		"├── 630 /usr/sbin/accounts-daemon",
		"└── 948 /usr/sbin/sshd -D",
		"    └── 2210 -bash",
	}
	if len(lines) != len(want) {
		t.Fatalf("tree lines = %d, want %d: %q", len(lines), len(want), lines)
	}
	for index, line := range want {
		if lines[index] != line {
			t.Errorf("line %d = %q, want %q", index, lines[index], line)
		}
	}
}

// A node whose parent the block does not hold — the process the collection
// missed, the node the display budget hid — starts a root, and its own children
// still hang from it.
func TestTreeDrawsAChildWhoseParentIsMissingAsARoot(t *testing.T) {
	lines := processTree.Render(treeBlock(
		node("948", "1", "/usr/sbin/sshd -D"),
		node("2210", "948", "-bash"),
	), model.RenderOptions{Width: 80})
	want := []string{"948 /usr/sbin/sshd -D", "└── 2210 -bash"}
	if len(lines) != len(want) || lines[0] != want[0] || lines[1] != want[1] {
		t.Fatalf("tree = %q, want %q", lines, want)
	}
}

// A hit paints the bytes the rule named when the node's line draws that column,
// and the whole node when it does not: the account a condition named is not on
// the line, and the node is what matched.
func TestTreePaintsTheHits(t *testing.T) {
	medium := SeverityPaint(model.Medium).Style()
	command := node("2210", "948", "/bin/sh -c id")
	command.Matches = []model.Match{hit("service-shell", model.Medium, "webshell", 3, 0, 7)}
	lines := processTree.Render(treeBlock(command), model.RenderOptions{Width: 80, Color: true})
	if !strings.Contains(lines[0], medium.Render("/bin/sh")) {
		t.Errorf("the named bytes should be painted: %q", lines[0])
	}
	if strings.Contains(lines[0], medium.Render("-c id")) {
		t.Errorf("the hit should stop where the span does: %q", lines[0])
	}

	account := node("2210", "948", "/bin/sh")
	account.Rec.Fields[2].Value = "www-data"
	account.Matches = []model.Match{hit("service-shell", model.Medium, "webshell", 2, 0, 8)}
	lines = processTree.Render(treeBlock(account), model.RenderOptions{Width: 80, Color: true})
	if !strings.Contains(lines[0], medium.Render("2210 /bin/sh")) {
		t.Errorf("a hit on a column the line does not draw paints the node: %q", lines[0])
	}
}

// The reason a node's hits state hangs under the branch with the node's own
// label, so it reads as belonging to the node and to nothing below it.
func TestTreeHangsTheReasonUnderTheBranch(t *testing.T) {
	item := node("2210", "948", "/tmp/x")
	item.Matches = []model.Match{hit("tmp-path", model.Medium, "temp path", 3, 0, 6)}
	lines := processTree.Render(treeBlock(item), model.RenderOptions{Width: 80, Color: true})
	if len(lines) != 2 || !strings.Contains(lines[0], "/tmp/x") {
		t.Fatalf("a root's label is its own line, got %q", lines)
	}
	if lines[1] != DimPaint().Style().Render("⟨temp path⟩") {
		t.Errorf("a root's reason hangs under the node: %q", lines[1])
	}

	child := node("2210", "948", "/tmp/x")
	child.Matches = []model.Match{hit("tmp-path", model.Medium, "temp path", 3, 0, 6)}
	parent := node("948", "1", "/usr/sbin/sshd -D")
	lines = processTree.Render(treeBlock(parent, child), model.RenderOptions{Width: 80, Color: true})
	if len(lines) != 3 || !strings.Contains(lines[1], LevelPaint(1).Style().Render("└── ")) {
		t.Fatalf("the child hangs from its parent with its level's hue on the lead: %q", lines)
	}
	if want := "    " + DimPaint().Style().Render("⟨temp path⟩"); lines[2] != want {
		t.Errorf("the reason should hang under the branch at the label's edge: %q", lines[2])
	}
}

// A node wider than the panel wraps, and its continuation hangs under the
// branch at the label's own edge: no line reaches past the width the form was
// given, and nothing is cut.
func TestTreeWrapsToThePanel(t *testing.T) {
	const width = 40
	long := strings.Repeat("/very/long", 8)
	lines := processTree.Render(treeBlock(
		node("1", "0", "/sbin/init"),
		node("2210", "1", long),
	), model.RenderOptions{Width: width})
	if len(lines) < 4 {
		t.Fatalf("the wide label should wrap under its branch: %q", lines)
	}
	for _, line := range lines {
		if got := lipgloss.Width(line); got > width {
			t.Errorf("a line should fit the panel (%d): %d %q", width, got, line)
		}
	}
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "…") {
		t.Errorf("nothing should be cut: %q", lines)
	}
	if tail := long[len(long)-10:]; !strings.Contains(joined, tail) {
		t.Errorf("the whole label should be printed, tail %q missing: %q", tail, lines)
	}
}

// Off a terminal the nest is the same drawing with no escapes at all.
func TestTreeIsPlainOffATerminal(t *testing.T) {
	item := node("1", "0", "/tmp/x")
	item.Matches = []model.Match{hit("tmp-path", model.Medium, "temp path", 3, 0, 6)}
	lines := processTree.Render(treeBlock(item, node("2210", "1", "-bash")), model.RenderOptions{Width: 80})
	if strings.Contains(strings.Join(lines, "\n"), "\x1b") {
		t.Errorf("a tree without color should carry no escapes: %q", lines)
	}
	if lines[2] != "└── 2210 -bash" {
		t.Errorf("the plain nest should read as the drawing: %q", lines)
	}
}

// The counted gap the display budget left is a structural row after the nest:
// the form draws the nodes it was given, so a hidden node's children are drawn
// as the roots they became.
func TestTreeKeepsTheCallersNote(t *testing.T) {
	lines := processTree.Render(treeBlock(
		node("1", "0", "/sbin/init"),
		model.BlockItem{Note: "… 12 lines"},
	), model.RenderOptions{Width: 80})
	if len(lines) != 2 || lines[1] != "… 12 lines" {
		t.Fatalf("the note should follow the nest: %q", lines)
	}
}

// The lead carries the level's hue: each bar the hue of the level it descends
// from, the glyph the node's own — the same cycle a table's columns read, so a
// nest and a grid speak one color language. A gap segment stays plain, and the
// label is left for the hits.
func TestTreePaintsTheLeadByLevel(t *testing.T) {
	lines := processTree.Render(treeBlock(
		node("1", "0", "/sbin/init"),
		node("948", "1", "/usr/sbin/sshd -D"),
		node("2210", "948", "-bash"),
		node("999", "1", "cron"),
	), model.RenderOptions{Width: 80, Color: true})
	// Roots first, siblings in pid order: the root, 948 (mid), its child, 999.
	if len(lines) != 4 {
		t.Fatalf("tree lines = %d: %q", len(lines), lines)
	}
	if lines[0] != "1 /sbin/init" {
		t.Fatalf("a root's own line carries no branch and stays plain: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], LevelPaint(1).Style().Render("├── ")) {
		t.Errorf("a first-level glyph should take the cycle's first tint: %q", lines[1])
	}
	want := LevelPaint(1).Style().Render("│   ") + LevelPaint(2).Style().Render("└── ")
	if !strings.HasPrefix(lines[2], want) {
		t.Errorf("a bar keeps its level's hue and the glyph takes the node's: %q", lines[2])
	}
	if !strings.HasPrefix(lines[3], LevelPaint(1).Style().Render("└── ")) {
		t.Errorf("the closing sibling takes the first level's hue: %q", lines[3])
	}
}
