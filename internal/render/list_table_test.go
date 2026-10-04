package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"karma/internal/model"
)

// testCatalog is a small two-platform catalog with the shapes that stress the
// layout: a long id, a long title, a six-tier chain, and a one-probe chain.
func testCatalog() []*model.Check {
	check := func(id, title string, platform model.Platform, aspect model.Aspect, chain ...string) *model.Check {
		probes := make([]model.Probe, 0, len(chain))
		for _, label := range chain {
			probes = append(probes, model.Probe{Label: label})
		}
		return &model.Check{ID: id, Title: title, Platform: platform, Aspect: aspect, Probes: probes}
	}
	return []*model.Check{
		check("os-release", "Distro and kernel", model.Linux, model.AspectSystem, "cat"),
		check("uptime", "Hostname and boot time", model.Linux, model.AspectSystem, "uptime", "proc-uptime"),
		check("accounts", "Accounts", model.Linux, model.AspectIdentity, "getent", "cat"),
		check("authorized-keys", "SSH authorized keys", model.Linux, model.AspectIdentity, "find"),
		check("run-keys", "Autorun Entries (Run Keys and Startup Folders)", model.Windows, model.AspectPersistence,
			"reg", "hklm-run", "hklm-runonce", "hklm-wow", "hkcu-run", "hkcu-runonce"),
	}
}

func renderList(checks []*model.Check, width int) []string {
	var out bytes.Buffer
	RenderListTable(&out, checks, width)
	return strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
}

// The catalog is folded into consecutive platform/aspect groups under two levels
// of full-width bands: one platform band per platform, one aspect band per
// group, so a platform is announced once instead of once per group, and the rows
// keep catalog order.
func TestRenderListTableGroupsByPlatformAndAspect(t *testing.T) {
	lines := renderList(testCatalog(), 100)
	// The band color tells the levels apart: 236 is a platform, 238 an aspect.
	var bands, headings []string
	for _, line := range lines {
		switch {
		case strings.Contains(line, "48;5;236m"):
			bands = append(bands, strings.TrimRight(plain(line), " "))
		case strings.Contains(line, "48;5;238m"):
			headings = append(headings, strings.TrimRight(plain(line), " "))
		}
	}
	wantBands := []string{" LINUX", " WINDOWS"}
	if len(bands) != len(wantBands) {
		t.Fatalf("bands: got %q, want %q", bands, wantBands)
	}
	for i, band := range bands {
		if band != wantBands[i] {
			t.Errorf("band %d: got %q, want %q", i, band, wantBands[i])
		}
	}
	wantHeadings := []string{" SYSTEM", " IDENTITY", " PERSISTENCE"}
	if len(headings) != len(wantHeadings) {
		t.Fatalf("headings: got %q, want %q", headings, wantHeadings)
	}
	for i, heading := range headings {
		if heading != wantHeadings[i] {
			t.Errorf("heading %d: got %q, want %q", i, heading, wantHeadings[i])
		}
	}
	if count := strings.Count(plain(strings.Join(lines, "\n")), "LINUX"); count != 1 {
		t.Errorf("a platform should be named once, found LINUX %d times", count)
	}
	// The rows carry id, title, and chain, and the identity group follows the
	// system group.
	body := plain(strings.Join(lines, "\n"))
	for _, want := range []string{"os-release", "Distro and kernel", "uptime → proc-uptime", "authorized-keys"} {
		if !strings.Contains(body, want) {
			t.Errorf("listing should contain %q", want)
		}
	}
	if strings.Index(body, "os-release") > strings.Index(body, "accounts") {
		t.Error("rows should keep catalog order")
	}
}

// Nothing exceeds the line: the chain is capped, the title wraps inside its
// column, and a narrow terminal drops the chain before it breaks the fit.
func TestRenderListTableFitsTheLine(t *testing.T) {
	for _, width := range []int{160, 120, 100, 80, 60, 40} {
		for index, line := range renderList(testCatalog(), width) {
			if got := lipgloss.Width(line); got > lineWidth(width) {
				t.Errorf("width %d: line %d is %d cells: %q", width, index, got, plain(line))
			}
		}
	}
}

// A wrapped title keeps the rows to its right in place: the continuation starts
// at the title column and the chain column never moves.
func TestRenderListTableWrappedTitleKeepsColumns(t *testing.T) {
	const width = 80
	idColWidth, _, _ := listLayout(testCatalog(), width)
	lines := renderList(testCatalog(), width)
	var idColumn, chainColumns []int
	for _, line := range lines {
		text := strings.TrimRight(plain(line), " ")
		switch {
		case strings.HasPrefix(text, "  os-release"):
			idColumn = append(idColumn, strings.Index(text, "Distro"))
			chainColumns = append(chainColumns, strings.Index(text, "cat"))
		case strings.HasPrefix(text, "  run-keys"):
			chainColumns = append(chainColumns, strings.Index(text, "reg"))
		}
	}
	if len(idColumn) == 0 || idColumn[0] != listRowIndent+idColWidth+listGap {
		t.Fatalf("the title column should start after the id cell: %v", idColumn)
	}
	if len(chainColumns) < 2 || chainColumns[0] != chainColumns[1] {
		t.Fatalf("the chain column should not move between rows: %v", chainColumns)
	}
}

// A selection of one check sizes the columns to that check: none of the rest of
// the catalog reserves width, and the heading tree still names the platform and
// the aspect.
func TestRenderListTableSizesToSelection(t *testing.T) {
	lines := renderList(testCatalog()[3:4], 100)
	if len(lines) != 3 {
		t.Fatalf("a platform band, an aspect band, and a row: got %q", lines)
	}
	if text := strings.TrimSpace(plain(lines[0])); text != "LINUX" {
		t.Fatalf("band: %q", text)
	}
	if text := strings.TrimSpace(plain(lines[1])); text != "IDENTITY" {
		t.Fatalf("heading: %q", text)
	}
	if text := plain(lines[2]); !strings.HasPrefix(text, "  authorized-keys") {
		t.Fatalf("row: %q", text)
	}
}

// The heading tree and the id column carry their own colors: the platform band
// and the aspect band are two shades of the band background, and the ids are
// blue.
func TestRenderListTableColors(t *testing.T) {
	var out bytes.Buffer
	RenderListTable(&out, testCatalog(), 100)
	text := out.String()
	for _, want := range []string{"48;5;236m", "48;5;238m"} {
		if !strings.Contains(text, want) {
			t.Errorf("the heading bands should carry %s", want)
		}
	}
	if !strings.Contains(text, "\x1b[34m") {
		t.Error("the id column should be blue")
	}
}

func TestListLayoutDropsTheChainWhenNarrow(t *testing.T) {
	if _, titleW, chainW := listLayout(testCatalog(), 60); chainW != 0 || titleW <= 0 {
		t.Fatalf("a narrow line should drop the chain: title %d, chain %d", titleW, chainW)
	}
	if _, _, chainW := listLayout(testCatalog(), 120); chainW == 0 {
		t.Fatal("a wide line should carry the chain")
	}
}

func TestGroupChecksFoldsRuns(t *testing.T) {
	groups := groupChecks(testCatalog())
	if len(groups) != 3 {
		t.Fatalf("groups: %d, want 3", len(groups))
	}
	if groups[0].aspect != model.AspectSystem || len(groups[0].checks) != 2 {
		t.Errorf("first group: %s with %d checks", groups[0].aspect, len(groups[0].checks))
	}
	if groups[2].platform != model.Windows || len(groups[2].checks) != 1 {
		t.Errorf("last group: %s with %d checks", groups[2].platform, len(groups[2].checks))
	}
}
