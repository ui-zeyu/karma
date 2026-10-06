package render

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"

	"karma/internal/model"
)

// headerStart is the clock the masthead test renders with, in a fixed zone so
// the assertion does not depend on where the test runs.
var headerStart = time.Date(2026, 10, 6, 12, 11, 4, 0, time.FixedZone("CST", 8*3600))

// headerLabels are the masthead's fact labels, and headerLabelColumn is where
// the block's label column starts inside the panel: the rail and the body's own
// padding.
var headerLabels = []string{
	"host", "channel", "distro", "account", "kernel", "checks", "started", "severity",
}

const headerLabelColumn = 1 + bodyPad

func linuxFacts() model.HostFacts {
	return model.HostFacts{
		Hostname: "web-01",
		OsPretty: "Ubuntu 26.04.1 LTS",
		Kernel:   "7.0.0-22-generic",
		UID:      0,
	}
}

// headerLines renders one masthead and splits the plain text into its lines.
func headerLines(t *testing.T, facts model.HostFacts, info HeaderInfo, width int) (string, []string) {
	t.Helper()
	var out bytes.Buffer
	RenderHeader(&out, facts, info, width)
	body := plain(out.String())
	return body, strings.Split(strings.TrimRight(body, "\n"), "\n")
}

// labelPositions is where each of the block's labels starts in one row.
func labelPositions(line string) map[string]int {
	found := map[string]int{}
	for _, label := range headerLabels {
		if at := strings.Index(line, label); at >= 0 {
			found[label] = at
		}
	}
	return found
}

// column is the display column a byte offset falls in.
func column(line string, offset int) int { return lipgloss.Width(line[:offset]) }

// The report header is the report's first panel: the `KARMA` band — the same
// full-width level-one strip an aspect banner wears, covering the rail's own
// column — over the panel's level-two head band, which carries the build's
// version and the run's clock, and then a table of labeled facts. The facts line
// up as a table, two to a row, rather than running together behind dots.
func TestRenderHeader(t *testing.T) {
	body, lines := headerLines(t, linuxFacts(), HeaderInfo{
		Channel: "ssh root@47.93.135.155", Version: "9.9.9", Started: headerStart,
		Selected: 77, Total: 77,
	}, 100)

	for _, want := range []string{
		"KARMA", "9.9.9", "2026-10-06 12:11:04 +0800",
		"web-01", "root (uid 0)", "ssh root@47.93.135.155",
		"Ubuntu 26.04.1 LTS", "7.0.0-22-generic", "77",
		"severity", "critical", "high", "medium", "low",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("header should carry %q:\n%s", want, body)
		}
	}
	if !strings.HasPrefix(lines[0], " KARMA") || strings.Contains(lines[0], "▌") {
		t.Fatalf("the masthead opens with the KARMA band over the rail's column:\n%s", body)
	}
	if want := lineWidth(100); lipgloss.Width(lines[0]) != want {
		t.Fatalf("the title band is %d columns wide, an aspect banner is %d:\n%s",
			lipgloss.Width(lines[0]), want, body)
	}
	// The author rides the same band, on its right edge: the label/meta shape
	// every panel head wears, ending where every line ends (one column of slack).
	if byline := strings.TrimRight(lines[0], " "); !strings.HasSuffix(byline, authorLabel) {
		t.Fatalf("the title band should carry the author on its right edge:\n%s", body)
	}
	if end := column(lines[0], strings.LastIndex(lines[0], authorLabel)+len(authorLabel)); end != lineWidth(100)-rightPad {
		t.Fatalf("the author ends at column %d, the band's right edge is %d:\n%s", end, lineWidth(100)-rightPad, body)
	}
	if !strings.HasPrefix(lines[1], "▌ 9.9.9") {
		t.Fatalf("the panel's second-level band carries the version:\n%s", body)
	}
	for index, line := range lines[2:] {
		if !strings.HasPrefix(line, "▌") {
			t.Fatalf("fact row %d is outside the panel rail:\n%s", index, body)
		}
	}

	// The block is a table: every label starts in its column, is padded to the
	// block's label column, and its value starts in the value column behind it.
	// Positions are display columns: the rail is one column but three bytes.
	labelWidth := len("severity")
	grid := lines[2:]
	second := column(grid[0], strings.Index(grid[0], "channel"))
	if second <= headerLabelColumn {
		t.Fatalf("the first row should carry two facts, the second at column %d:\n%s", second, body)
	}
	for _, line := range grid {
		found := labelPositions(line)
		if len(found) == 0 {
			t.Fatalf("row %q carries no label:\n%s", line, body)
		}
		for label, at := range found {
			if got := column(line, at); got != headerLabelColumn && got != second {
				t.Fatalf("label %q starts at column %d; the block's columns are %d and %d:\n%s",
					label, got, headerLabelColumn, second, body)
			}
			if pad := line[at+len(label) : at+labelWidth]; strings.TrimSpace(pad) != "" {
				t.Fatalf("label %q is not padded to the label column: %q", label, line)
			}
			value := strings.TrimPrefix(line[at+labelWidth:], strings.Repeat(" ", factGap))
			if value == line[at+labelWidth:] || value == "" || value[0] == ' ' {
				t.Fatalf("value of %q does not start at the value column: %q", label, line)
			}
		}
	}
	if got := column(grid[0], labelPositions(grid[0])["host"]); got != headerLabelColumn {
		t.Fatalf("the first fact starts at column %d, the block's label column is %d:\n%s",
			got, headerLabelColumn, body)
	}

	for index, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if width := lipgloss.Width(line); width > 99 {
			t.Fatalf("header line %d is %d columns wide, over the line width: %q", index, width, line)
		}
	}
}

// The command-line skeleton's banner is the report's first panel: the same
// level-one band with the byline on its right edge, the version as the
// level-two head, and the caller's body inside the same rail.
func TestMastheadBanner(t *testing.T) {
	const width = 60
	body := plain(Masthead("karma local", "9.9.9",
		[]string{"Collect read-only evidence from the local host."}, width))
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("the banner is a band over a rail panel:\n%s", body)
	}
	if !strings.HasPrefix(lines[0], " KARMA LOCAL") {
		t.Fatalf("the band carries the caller's label:\n%s", body)
	}
	if got := lipgloss.Width(lines[0]); got != lineWidth(width) {
		t.Fatalf("the band is %d columns wide, a level-one band is %d:\n%s",
			got, lineWidth(width), body)
	}
	if byline := strings.TrimRight(lines[0], " "); !strings.HasSuffix(byline, authorLabel) {
		t.Fatalf("the band should carry the byline on its right edge:\n%s", body)
	}
	if end := column(lines[0], strings.LastIndex(lines[0], authorLabel)+len(authorLabel)); end != lineWidth(width)-rightPad {
		t.Fatalf("the byline ends at column %d, the band's right edge is %d:\n%s",
			end, lineWidth(width)-rightPad, body)
	}
	if head := strings.TrimRight(lines[1], " "); head != "▌ 9.9.9" {
		t.Fatalf("the panel head should carry the version alone, got %q:\n%s", head, body)
	}
	if !strings.Contains(body, "Collect read-only evidence from the local host.") {
		t.Fatalf("the body belongs inside the panel:\n%s", body)
	}
	for index, line := range lines[2:] {
		if !strings.HasPrefix(line, "▌") {
			t.Fatalf("body row %d is outside the rail:\n%s", index, body)
		}
	}

	// A caller with no body keeps the band and its version head: the help of a
	// command carrying no description is still the same shape.
	headless := plain(Masthead("karma version", "9.9.9", nil, width))
	if !strings.HasPrefix(headless, " KARMA VERSION") ||
		!strings.Contains(headless, "▌ 9.9.9") || strings.Contains(headless, "\n\n") {
		t.Fatalf("an empty body should leave the band over its head:\n%s", headless)
	}
}

// A narrowed run names its scope; a whole-catalog run names the whole catalog.
// The severity key keeps its own row and states the floor in force.
func TestRenderHeaderScope(t *testing.T) {
	body, _ := headerLines(t, linuxFacts(), HeaderInfo{
		Channel: "local", Version: "9.9.9", Started: headerStart,
		Selected: 6, Total: 77, Selectors: []string{"process", "log"},
		Floor: model.FloorAbove(model.Medium),
	}, 100)
	for _, want := range []string{"6 of 77 (process log)", "showing ≥ medium"} {
		if !strings.Contains(body, want) {
			t.Fatalf("header should carry %q:\n%s", want, body)
		}
	}

	body, _ = headerLines(t, linuxFacts(), HeaderInfo{
		Channel: "local", Version: "9.9.9", Started: headerStart, Selected: 77, Total: 77,
	}, 100)
	if !strings.Contains(body, "checks    77") {
		t.Fatalf("a whole-catalog run states its scope as one number:\n%s", body)
	}
}

// A Windows target reports its own account (the channel's USERDOMAIN\user) and
// its own system line; a line too narrow for two columns falls back to one.
func TestRenderHeaderWindowsAndNarrowLine(t *testing.T) {
	facts := model.HostFacts{
		Hostname: "WIN-DC01", User: `CORP\alice`, UID: -1,
		OsPretty: "Windows Server 2019 Datacenter 1809", Kernel: "10.0.17763.1",
	}
	info := HeaderInfo{Channel: "local", Version: "9.9.9", Started: headerStart,
		Selected: 43, Total: 43}
	body, _ := headerLines(t, facts, info, 100)
	for _, want := range []string{`CORP\alice`, "Windows Server 2019 Datacenter 1809", "43"} {
		if !strings.Contains(body, want) {
			t.Fatalf("header should carry %q:\n%s", want, body)
		}
	}

	body, lines := headerLines(t, facts, info, 60)
	for _, line := range lines[2:] {
		if found := labelPositions(line); len(found) != 1 {
			t.Fatalf("a narrow header carries one fact to a row, this one has %d:\n%s",
				len(found), body)
		}
	}
	for index, line := range lines {
		if width := lipgloss.Width(line); width > 59 {
			t.Fatalf("narrow header line %d is %d columns wide: %q", index, width, line)
		}
	}
}
