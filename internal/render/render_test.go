package render

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"karma/internal/checks"
	"karma/internal/form"
	"karma/internal/model"
	"karma/internal/reader"
	"karma/internal/testkit"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func plain(s string) string { return ansi.ReplaceAllString(s, "") }

// SyntaxPainter is the report's body-line coloring handed to callers outside
// the report: an ls-l row comes back with the ls-l paint and strips back to
// itself, and an unknown syntax has no painter at all.
func TestSyntaxPainter(t *testing.T) {
	row := "drwxr-xr-x 2 root root 4096 Oct 06 12:00 /tmp/sub"
	paint := SyntaxPainter("ls-l")
	if paint == nil {
		t.Fatal("ls-l should have a painter")
	}
	painted := paint(row)
	if painted == row {
		t.Fatalf("the ls-l row should be colored: %q", painted)
	}
	if plain(painted) != row {
		t.Fatalf("the paint should not change the text: %q", painted)
	}
	if got := SyntaxPainter("no-such-syntax"); got != nil {
		t.Fatal("an unknown syntax should have no painter")
	}
}

// The test process's stdout is not a terminal, so lipgloss lands in the Ascii
// profile and comparing plain text would verify no coloring at all; pinning the
// 256-color profile makes this package's color assertions real.
func TestMain(m *testing.M) {
	lipgloss.SetColorProfile(termenv.ANSI256)
	os.Exit(m.Run())
}

// A check panel is a half-block left rail: the severity color for signals,
// muted otherwise, the id as the level-two band label and metadata right on
// the first line, and over-long lines soft-wrapped — not one word lost,
// continuation lines sharing the body indent, the rail unbroken. The per-line
// width assertions below also cover the CJK case: a title row carrying a CJK
// badge once shifted the border and collapsed the line width on a real Windows
// host (Server 2025, 146 columns).
func TestCheckPanelSignalRail(t *testing.T) {
	const width = 48
	long := strings.Repeat("allow from 203.0.113.0/24 ", 8)
	result := &model.CheckResult{
		Check:   &model.Check{ID: "listen", Aspect: model.AspectNetwork},
		Outcome: model.Collected,
		Document: model.Document{
			Filtered: []model.FilterCount{{ID: "drop", Count: 3}},
			Sections: []model.Section{{Lines: []model.Line{
				{
					Text: "tcp 0.0.0.0:22", Severity: model.High,
					Matches: []model.Match{{ID: "open", Severity: model.High, Message: "external listener",
						Spans: []model.Span{{Start: 0, End: 3}}}},
				},
				{Text: long, Severity: model.Info},
			}}},
		},
	}
	got := checkPanel(result, 40, width, true)
	lines := strings.Split(got, "\n")
	if len(lines) < 3 {
		t.Fatalf("panel too short: %q", plain(got))
	}
	head := plain(lines[0])
	if !strings.HasPrefix(head, "▌ ") {
		t.Fatalf("a signal panel should start with the half-block rail: %q", head)
	}
	if !strings.Contains(head, "LISTEN") {
		t.Fatalf("the first line should carry the check id: %q", head)
	}
	if !strings.Contains(head, "filtered 3") || strings.Index(head, "LISTEN") > strings.Index(head, "filtered 3") {
		t.Fatalf("metadata should be on the right: %q", head)
	}
	for i, line := range lines {
		if !strings.HasPrefix(plain(line), "▌") {
			t.Fatalf("line %d should carry the rail: %q", i, plain(line))
		}
		if got := lipgloss.Width(line); got > width-1 {
			t.Fatalf("line %d is %d wide, past the right-edge slack: %q", i, got, plain(line))
		}
	}
	if !strings.Contains(got, "⟨external listener⟩") {
		t.Fatalf("a finding row should carry the trailing reason: %q", plain(got))
	}
	// Soft wrap preserves everything: every word of the long line is present,
	// broken across several lines
	body := plain(strings.Join(lines[2:], "\n"))
	for _, word := range []string{"allow", "203.0.113.0/24"} {
		if !strings.Contains(body, word) {
			t.Fatalf("wrapping must not lose content (missing %q): %q", word, body)
		}
	}
	if strings.Count(body, "203.0.113.0/24") != 8 {
		t.Fatalf("all 8 addresses of the long line should survive: %q", body)
	}
	if len(lines)-2 < 4 {
		t.Fatalf("an over-long line should wrap onto several lines, got %d: %q", len(lines)-2, body)
	}
}

// Execution notes such as timeout/failure: with no body they still produce a
// thin grey rail panel, with the red note on the right of the first line.
func TestCheckPanelNoteBlock(t *testing.T) {
	result := &model.CheckResult{
		Check:   &model.Check{ID: "dmesg", Aspect: model.AspectKernel},
		Outcome: model.Failed,
		Note:    "timeout (30s), partial output kept",
		Raw:     "line one\nline two\n",
	}
	got := checkPanel(result, 400, 80, true)
	if got == "" {
		t.Fatal("a check with a note must not stay silent")
	}
	lines := strings.Split(got, "\n")
	if !strings.HasPrefix(plain(lines[0]), "▌ DMESG") || !strings.Contains(plain(lines[0]), "timeout (30s), partial output kept") {
		t.Fatalf("the first line should carry the id and the note: %q", plain(lines[0]))
	}
	noteStyle := style{FG: "9", Bold: true, BG: string(subBandColor)}
	if !strings.Contains(lines[0], noteStyle.Style().Render("timeout (30s), partial output kept")) {
		t.Fatalf("the note should be lit on the band: %q", lines[0])
	}
	if body := plain(strings.Join(lines[1:], "\n")); !strings.Contains(body, "line one") ||
		!strings.Contains(body, "line two") {
		t.Fatalf("a note panel should carry the raw text: %q", body)
	}
}

// A quiet check gets the grey rail; a check that was never collected and one
// collected with no content alike do not appear in the report.
func TestCheckPanelQuietRailAndSkippedLine(t *testing.T) {
	quiet := &model.CheckResult{
		Check:   &model.Check{ID: "passwd", Aspect: model.AspectIdentity},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{
			{Lines: []model.Line{{Text: "root:x:0:0:root:/root:/bin/bash", Severity: model.Info}}},
		}},
	}
	lines := strings.Split(checkPanel(quiet, 40, 80, true), "\n")
	quietRail := mutedStyle.Style().Render("▌")
	for i, line := range lines {
		if !strings.HasPrefix(plain(line), "▌ ") {
			t.Fatalf("a quiet panel should start with the grey rail (line %d): %q", i, plain(line))
		}
		if !strings.HasPrefix(line, quietRail) {
			t.Fatalf("the quiet panel's rail should be muted (line %d): %q", i, line)
		}
	}
	if head := plain(lines[0]); !strings.HasPrefix(head, "▌ PASSWD") {
		t.Fatalf("the first line should start with the id: %q", head)
	}

	skipped := &model.CheckResult{
		Check:         &model.Check{ID: "last-log", Aspect: model.AspectIdentity},
		Outcome:       model.Skipped,
		SkippedLabels: []string{"last", "lastlog"},
	}
	if got := checkPanel(skipped, 40, 80, true); got != "" {
		t.Fatalf("a check that was never collected should stay silent: %q", plain(got))
	}
	empty := &model.CheckResult{
		Check:    &model.Check{ID: "empty", Aspect: model.AspectIdentity},
		Outcome:  model.Collected,
		Document: model.Document{Sections: []model.Section{{}}},
	}
	if got := checkPanel(empty, 40, 80, true); got != "" {
		t.Fatalf("a check collected with no content should stay silent: %q", plain(got))
	}
}

// A section the reading layer kept for its title alone — a rule matched the
// `== path` header and every body row was filtered or below the floor — is
// still a finding: the panel prints the title and its reason.
func TestTitleOnlySectionIsShown(t *testing.T) {
	result := &model.CheckResult{
		Check:   &model.Check{ID: "hidden", Aspect: model.AspectFilesystem},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{{
			Title:        "/tmp/.evil",
			TitleMatches: []model.Match{{ID: "evil-path", Severity: model.High, Message: "hidden payload path"}},
		}}},
	}
	panel := plain(checkPanel(result, 40, 80, true))
	if !strings.Contains(panel, "/tmp/.evil") || !strings.Contains(panel, "hidden payload path") {
		t.Fatalf("a title-only finding lost its text or reason: %q", panel)
	}
}

// The level-one heading band fills the line width, is all uppercase, white on
// dark, and never exceeds the terminal.
func TestHeadingBand(t *testing.T) {
	const width = 60
	band := headingBand("identity", width)
	if got := lipgloss.Width(band); got != width-1 {
		t.Fatalf("the banner should fill %d columns, got %d", width-1, got)
	}
	if text := plain(band); !strings.HasPrefix(text, " IDENTITY") {
		t.Fatalf("the banner should be uppercase: %q", text)
	}
	if !strings.Contains(band, "\x1b[") {
		t.Fatalf("the banner should be colored: %q", band)
	}
	if narrow := headingBand("identity", 12); lipgloss.Width(narrow) != 11 {
		t.Fatalf("a narrow terminal should still be filled: %d", lipgloss.Width(narrow))
	}
}

// The check title is the heading tree's second step (the listing's aspect
// band): the band fills the panel from the rail to the right edge as one
// solid strip, the label is the uppercase id, and body rows carry no band.
func TestCheckPanelHeadIsASubBand(t *testing.T) {
	const width = 60
	result := &model.CheckResult{
		Check:   &model.Check{ID: "listen", Aspect: model.AspectNetwork},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{{Lines: []model.Line{
			{Text: "tcp 0.0.0.0:22", Severity: model.Info},
		}}}},
	}
	panel := checkPanel(result, 40, width, true)
	lines := strings.Split(panel, "\n")
	head := lines[0]
	if got := lipgloss.Width(head); got != railInner(width)+1 {
		t.Fatalf("the head band should fill rail + inner width (%d), got %d", railInner(width)+1, got)
	}
	if !strings.Contains(head, "48;5;238") {
		t.Fatalf("the head should sit on the level-two band: %q", head)
	}
	bandPaintedSpaces := regexp.MustCompile(`\x1b\[[0-9;]*48;5;238[0-9;]*m {2,}`)
	if !bandPaintedSpaces.MatchString(head) {
		t.Fatalf("the band's padding should be painted (solid strip): %q", head)
	}
	if label := plain(head); !strings.Contains(label, " LISTEN") {
		t.Fatalf("the band label should be the uppercase id: %q", label)
	}
	for i, line := range lines[1:] {
		if strings.Contains(line, "48;5;238") {
			t.Fatalf("body line %d should carry no band: %q", i+1, plain(line))
		}
	}

	// Metadata that does not fit beside the label drops to its own band row,
	// aligned with the label, both rows filled edge to edge.
	long := result
	long.Document.Truncated = true
	long.Document.Filtered = []model.FilterCount{{ID: "quiet", Count: 12}}
	long.Check.ID = "last-log"
	narrow := checkPanel(long, 40, 20, true)
	narrowLines := strings.Split(narrow, "\n")
	if plain(narrowLines[0]) == plain(narrowLines[1]) {
		t.Fatalf("the metadata should sit on its own band row:\n%s", plain(narrow))
	}
	for i := 0; i < 2; i++ {
		if got := lipgloss.Width(narrowLines[i]); got != railInner(20)+1 {
			t.Fatalf("narrow band row %d should still fill the panel: %d", i, got)
		}
	}
}

// A body row carrying a token lipgloss cannot break (a base64 argument with no
// separator) must not widen the panel past the line: the row is broken by
// character, and no part of the token is dropped.
func TestCheckPanelBoundsUnbreakableTokens(t *testing.T) {
	blob := strings.Repeat("QUJD", 40) // 160 cells, no break point
	result := &model.CheckResult{
		Check:   &model.Check{ID: "ps", Aspect: model.AspectProcess},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{{Lines: []model.Line{
			{Text: "501 1 0 0 Tue09AM ?? 0:00 x " + blob, Severity: model.Info},
		}}}},
	}
	panel := checkPanel(result, 40, 100, true)
	for index, line := range strings.Split(panel, "\n") {
		if got := lipgloss.Width(line); got > lineWidth(100) {
			t.Fatalf("line %d is %d cells wide: %q", index, got, plain(line))
		}
	}
	if !strings.Contains(plain(panel), "QUJDQUJD") {
		t.Fatal("the token should be broken across lines, not dropped")
	}
}

func TestPanelRenderPanicFallsBackToPlainBlock(t *testing.T) {
	original := panelRenderer
	defer func() { panelRenderer = original }()
	panelRenderer = func(*model.CheckResult, int, int, bool) string { panic("layout blew up") }
	result := &model.CheckResult{
		Check:   &model.Check{ID: "listen", Aspect: model.AspectNetwork},
		Outcome: model.Collected,
		Raw:     "tcp 0.0.0.0:22\n",
	}
	text, failed := renderPanel(result, 400, 100, true)
	if !failed || text == "" {
		t.Fatalf("a failed render should fall back to the grey block: failed=%v text=%q", failed, plain(text))
	}
	if !strings.Contains(plain(text), "LISTEN") || !strings.Contains(plain(text), "tcp 0.0.0.0:22") {
		t.Fatalf("the fallback block should keep the id and the raw text: %q", plain(text))
	}
}

func TestProgressDoesNotStickToPanels(t *testing.T) {
	var buf lockedBuffer
	check := &model.Check{ID: "listen", Aspect: model.AspectNetwork}
	obs := NewLiveObserver(&buf, []*model.Check{check}, 40, 48, true, true)
	obs.Start()
	obs.CheckStarted(check)
	time.Sleep(150 * time.Millisecond)
	if !strings.Contains(buf.String(), " 0/1 ") {
		t.Fatalf("the progress line should show 0/1 while the check runs: %q", buf.String())
	}
	obs.CheckFinished(check, &model.CheckResult{
		Check:   check,
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{{
			Lines: []model.Line{{
				Text: "tcp 0.0.0.0:22", Severity: model.High,
				Matches: []model.Match{{
					ID: "open", Severity: model.High, Message: "external listener",
					Spans: []model.Span{{Start: 0, End: 3}},
				}},
			}},
		}}},
	})
	time.Sleep(150 * time.Millisecond)
	if !strings.Contains(buf.String(), " 1/1 ") {
		t.Fatalf("the progress line should count the finished check (a channel address would print here): %q", buf.String())
	}
	obs.Close()

	visible := strings.Join(screen(buf.String()), "\n")
	if !strings.Contains(visible, "LISTEN") || !strings.Contains(visible, "▌") {
		t.Fatalf("the check panel should remain:\n%s", visible)
	}
	for _, line := range strings.Split(visible, "\n") {
		if strings.Contains(line, "▌") && strings.Contains(line, "1/1") {
			t.Fatalf("the progress count stuck to the rail: %q", line)
		}
		for _, frame := range spinnerFrames {
			if strings.Contains(line, frame) {
				t.Fatalf("a progress glyph stayed on screen: %q\n%s", line, visible)
			}
		}
	}
}

// lockedBuffer is a bytes.Buffer the test may read while the observer loop
// writes: the loop goroutine owns the writes, and String takes the same lock.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// screen replays terminal semantics: \r returns to column 0, CSI K clears to
// end of line, newline commits.
func screen(raw string) []string {
	var lines []string
	var cur []rune
	col := 0
	for i := 0; i < len(raw); {
		switch {
		case raw[i] == '\n':
			lines = append(lines, string(cur))
			cur, col = nil, 0
			i++
		case raw[i] == '\r':
			col = 0
			i++
		case strings.HasPrefix(raw[i:], "\033[K"):
			if col < len(cur) {
				cur = cur[:col]
			}
			i += len("\033[K")
		case raw[i] == '\033':
			i++
			for i < len(raw) && (raw[i] < 0x40 || raw[i] > 0x7e) {
				i++
			}
			if i < len(raw) {
				i++
			}
		default:
			r, size := utf8.DecodeRuneInString(raw[i:])
			if col < len(cur) {
				cur[col] = r
			} else {
				cur = append(cur, r)
			}
			col++
			i += size
		}
	}
	if len(cur) > 0 {
		lines = append(lines, string(cur))
	}
	return lines
}

func TestSeverityBorderHue(t *testing.T) {
	if severityBorder(model.Critical) != "1" || severityBorder(model.High) != "9" {
		t.Fatalf("border hues: critical %q high %q", severityBorder(model.Critical), severityBorder(model.High))
	}
	if severityBorder(model.Medium) != "11" || severityBorder(model.Low) != "14" {
		t.Fatalf("border hues: medium %q low %q", severityBorder(model.Medium), severityBorder(model.Low))
	}
}

// Section titles are bold plain text (default color) and hits carry a trailing
// reason; sections are separated by one blank line.
func TestBodyRowsSectionBlocks(t *testing.T) {
	result := &model.CheckResult{
		Check:   &model.Check{ID: "cron", Aspect: model.AspectPersistence},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{
			{
				Title: "/etc/cron.d/evil",
				TitleMatches: []model.Match{{ID: "cron-reboot", Severity: model.High, Message: "reboot trigger",
					Spans: []model.Span{{Start: 5, End: 10}}}},
				Lines: []model.Line{{
					Text: "@reboot cmd", Severity: model.High,
					Matches: []model.Match{{ID: "cron-reboot", Severity: model.High, Message: "reboot trigger",
						Spans: []model.Span{{Start: 0, End: 7}}}},
				}},
			},
			{
				Title: "/etc/crontab",
				Lines: []model.Line{{Text: "daily job", Severity: model.Info}},
			},
		}},
	}
	rows := bodyRows(result, 400, 100, true)
	if got := plain(rows[0]); got != "/etc/cron.d/evil  ⟨reboot trigger⟩" {
		t.Fatalf("the section title should come before the body, with the trailing reason: %q", got)
	}
	if !strings.Contains(rows[0], style{Bold: true}.Style().Render("/etc/")) {
		t.Fatalf("the section title should be bold plain text: %q", rows[0])
	}
	if strings.Contains(rows[0], mutedStyle.Style().Render("/etc/")) {
		t.Fatalf("the section title should no longer be muted: %q", rows[0])
	}
	if got := plain(rows[1]); got != "@reboot cmd  ⟨reboot trigger⟩" {
		t.Fatalf("below the section title comes the body row with its reason: %q", got)
	}
	if rows[2] != "" {
		t.Fatalf("sections should be separated by one blank line: %q", plain(rows[2]))
	}
	if plain(rows[3]) != "/etc/crontab" {
		t.Fatalf("a quiet section title is plain: %q", plain(rows[3]))
	}
}

// The preamble (output before any section header) comes first, separated from
// the section title by one blank line.
func TestBodyRowsPreludeComesFirst(t *testing.T) {
	result := &model.CheckResult{
		Check:   &model.Check{ID: "mixed", Aspect: model.AspectIdentity},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{
			{Lines: []model.Line{{Text: "raw prelude", Severity: model.Info}}},
			{Title: "/etc/passwd", Lines: []model.Line{{Text: "root:x:0:0:", Severity: model.Info}}},
		}},
	}
	rows := bodyRows(result, 400, 100, true)
	if plain(rows[0]) != "raw prelude" {
		t.Fatalf("the preamble should come first: %q", plain(rows[0]))
	}
	if rows[1] != "" || plain(rows[2]) != "/etc/passwd" {
		t.Fatalf("the preamble and the section should be separated by one blank line: %q", plain(strings.Join(rows, "|")))
	}
}

// A failed render falls back to a thin grey rail with the raw text, keeping the
// id and the text.
func TestFallbackPanelKeepsRawText(t *testing.T) {
	result := &model.CheckResult{
		Check:   &model.Check{ID: "listen", Aspect: model.AspectNetwork},
		Outcome: model.Collected,
		Raw:     "tcp 0.0.0.0:22\n",
	}
	text := fallbackPanel(result, 400, 100)
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(plain(line), "▌") {
			t.Fatalf("the fallback block should be a grey rail: %q", plain(line))
		}
	}
	if joined := plain(text); !strings.Contains(joined, "LISTEN") || !strings.Contains(joined, "tcp 0.0.0.0:22") {
		t.Fatalf("the fallback block should keep the id and the raw text: %q", joined)
	}
}

// A section override styles that section with its own rule; the rest keep the
// check syntax. Glob titles let dynamic per-file sections match too.
func TestSectionSyntaxOverridesByTitle(t *testing.T) {
	check := &model.Check{
		ID: "skel", Syntax: model.SyntaxBash,
		SectionSyntax: []model.SectionSyntax{
			{Title: "/etc/skel", Syntax: model.SyntaxLsL},
			{Title: "/home/*/.*_history", Syntax: model.SyntaxColon},
		},
	}
	if got := sectionSyntax(check, "/etc/skel"); got != "ls-l" {
		t.Fatalf("the listing section should take the override: %q", got)
	}
	if got := sectionSyntax(check, "/etc/skel/.bashrc"); got != "bash" {
		t.Fatalf("other sections keep the check syntax: %q", got)
	}
	if got := sectionSyntax(check, "/home/deploy/.zsh_history"); got != "colon" {
		t.Fatalf("a glob should match dynamic titles: %q", got)
	}
	if got := sectionSyntax(&model.Check{Syntax: model.SyntaxBash}, "/etc/skel"); got != "bash" {
		t.Fatalf("no overrides means the check syntax everywhere: %q", got)
	}
}

// End to end through the panel: a services document rendered under the units
// syntax paints the state cells by meaning.
func TestUnitsPanelPaintsStateCells(t *testing.T) {
	result := &model.CheckResult{
		Check:   &model.Check{ID: "services", Aspect: model.AspectService, Syntax: model.SyntaxUnits},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{{Lines: []model.Line{
			{Text: "UNIT             LOAD   ACTIVE   SUB        DESCRIPTION", Severity: model.Info},
			{Text: "sshd.service     loaded active   running    OpenBSD server", Severity: model.Info},
			{Text: "certbot.service  loaded active   exited     Certbot renewal", Severity: model.Info},
		}}}},
	}
	panel := checkPanel(result, 40, 120, true)
	if !strings.Contains(panel, style{FG: "2"}.Style().Render("running")) {
		t.Fatalf("running should be green in the panel:\n%s", plain(panel))
	}
	if !strings.Contains(panel, dimStyle.Style().Render("exited")) {
		t.Fatalf("exited should be faint in the panel:\n%s", plain(panel))
	}
}

// End to end through the panel: the SysV rows the services check also collects
// (`service --status-all`) paint the bracketed marker as one field in its state
// color — not one color per glyph — and the name in the first column color, the
// one the systemd table gives its UNIT column.
func TestUnitsPanelPaintsSysvStateMarkers(t *testing.T) {
	result := &model.CheckResult{
		Check:   &model.Check{ID: "services", Aspect: model.AspectService, Syntax: model.SyntaxUnits},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{{Title: "service", Lines: []model.Line{
			{Text: " [ + ]  apache2", Severity: model.Info},
			{Text: " [ - ]  cron", Severity: model.Info},
			{Text: " [ ? ]  dnsmasq", Severity: model.Info},
		}}}},
	}
	panel := checkPanel(result, 40, 120, true)
	if !strings.Contains(panel, style{FG: "2"}.Style().Render("[ + ]")) {
		t.Fatalf("a running marker should be green as one field:\n%s", plain(panel))
	}
	if !strings.Contains(panel, dimStyle.Style().Render("[ - ]")) ||
		!strings.Contains(panel, dimStyle.Style().Render("[ ? ]")) {
		t.Fatalf("stopped and unknown markers should be Faint:\n%s", plain(panel))
	}
	if !strings.Contains(panel, form.ColumnPaint(0).Style().Render("apache2")) {
		t.Fatalf("the service name should take the first column color:\n%s", plain(panel))
	}
}

// Two signal rules over the same text: the painted span follows the reason, so
// the more severe rule wins whichever way the catalog orders them.
func TestLineTextMostSevereSpanWins(t *testing.T) {
	const text = "cap_setuid=ep"
	match := func(id string, severity model.Severity) model.Match {
		return model.Match{ID: id, Severity: severity, Message: id,
			Spans: []model.Span{{Start: 0, End: len(text)}}}
	}
	for _, matches := range [][]model.Match{
		{match("caps-setuid", model.Critical), match("caps-present", model.Low)},
		{match("caps-present", model.Low), match("caps-setuid", model.Critical)},
	} {
		got := lineText(model.Line{Text: text, Severity: model.Critical, Matches: matches}, nil)
		if !strings.Contains(got, form.SeverityPaint(model.Critical).Style().Render(text)) {
			t.Fatalf("the critical span should paint over the lower one (order %v): %q", matches[0].ID, got)
		}
	}
}

// End to end through the panel: one panel, two section rules — the skel
// listing keeps the ls -l colors while the collected shell file keeps the
// bash lexer.
func TestSkelPanelKeepsLsColorsForTheListing(t *testing.T) {
	result := &model.CheckResult{
		Check: &model.Check{
			ID: "skel", Aspect: model.AspectPersistence, Syntax: model.SyntaxBash,
			SectionSyntax: []model.SectionSyntax{{Title: "/etc/skel", Syntax: model.SyntaxLsL}},
		},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{
			{Title: "/etc/skel", Lines: []model.Line{
				{Text: "-rw-r--r-- 1 root root 921 Jan 01 12:34 /etc/skel/.bashrc", Severity: model.Info},
			}},
			{Title: "/etc/skel/.bashrc", Lines: []model.Line{
				{Text: "export EDITOR=vim", Severity: model.Info},
			}},
		}},
	}
	panel := checkPanel(result, 40, 120, true)
	if !strings.Contains(panel, style{FG: "2"}.Style().Render("Jan 01 12:34")) {
		t.Fatalf("the listing should keep the ls -l colors:\n%s", plain(panel))
	}
	// The bash lexer paints a keyword in internal/syntax's own magenta.
	if !strings.Contains(panel, style{FG: "5"}.Style().Render("export")) {
		t.Fatalf("the shell section should keep the bash lexer:\n%s", plain(panel))
	}
}

// df is drawn by the check's form rather than by a lexer: the reading turns the
// tool's table into records and the form lays the six columns out — the header
// printed once, the numeric cells at their column's right edge — so a body of
// aligned columns reaches the panel as the table it is.
func TestDfPanelDrawsTheTable(t *testing.T) {
	check := testkit.CheckByID(t, checks.ChecksFor(model.Linux), "df")
	document := reader.Read(model.ReadRequest{
		Check: check,
		Body: model.Body{Sections: []model.BodySection{{Text: "Filesystem      Size  Used Avail Use% Mounted on\n" +
			"/dev/vda1        40G   15G   25G  38% /\n" +
			"tmpfs           391M     0  391M   0% /dev/shm\n"}}},
		Floor: model.FloorAll,
	})
	rows := bodyRows(&model.CheckResult{Check: check, Outcome: model.Collected, Document: document}, 400, 100, false)
	if len(rows) != 3 {
		t.Fatalf("a header and one row per filesystem: %q", rows)
	}
	if !strings.HasPrefix(rows[0], "Filesystem") {
		t.Fatalf("the form prints the header: %q", rows)
	}
	if strings.Count(strings.Join(rows, "\n"), "Filesystem") != 1 {
		t.Fatalf("the header is printed once, not as a row too: %q", rows)
	}
	// The right edge is the alignment the check declares for the numeric cells:
	// both rows' sizes end in one column, and so do their percentages.
	end := func(row, token string) int { return strings.Index(row, token) + len(token) }
	if a, b := end(rows[1], "40G"), end(rows[2], "391M"); a != b {
		t.Fatalf("the size column should be right-aligned: %q", rows)
	}
	if a, b := end(rows[1], "38%"), end(rows[2], "0%"); a != b {
		t.Fatalf("the use column should be right-aligned: %q", rows)
	}
	if !strings.HasSuffix(rows[1], "/") || !strings.HasSuffix(rows[2], "/dev/shm") {
		t.Fatalf("the mount point is the last column: %q", rows)
	}
}

func TestFstabPanelDrawsRecordsAndRemarks(t *testing.T) {
	check := testkit.CheckByID(t, checks.ChecksFor(model.Linux), "fstab")
	body := "# /etc/fstab: static file system information.\n" +
		"LABEL=cloudimg-rootfs  /  ext4  discard,errors=remount-ro  0 1\n"
	document := reader.Read(model.ReadRequest{
		Check: check,
		Body:  model.Body{Sections: []model.BodySection{{Title: "/etc/fstab", Text: body}}},
		Floor: model.FloorAll,
	})
	rows := plainAll(bodyRows(&model.CheckResult{Check: check, Outcome: model.Collected, Document: document}, 400, 100, false))
	if len(rows) != 4 {
		t.Fatalf("title, head, remark and row: %q", rows)
	}
	if rows[0] != "/etc/fstab" || !strings.HasPrefix(rows[1], "Device") || !strings.HasSuffix(rows[1], "Pass") {
		t.Fatalf("the head names the file's six fields: %q", rows[:2])
	}
	if rows[2] != "# /etc/fstab: static file system information." {
		t.Fatalf("a comment is the line it is: %q", rows[2])
	}
	if got := strings.Join(strings.Fields(rows[3]), " "); got != "LABEL=cloudimg-rootfs / ext4 discard,errors=remount-ro 0 1" {
		t.Fatalf("the record is the table's row: %q", rows[3])
	}
}

// plainAll is rows with the panel's own escapes stripped.
func plainAll(rows []string) []string {
	out := make([]string, len(rows))
	for index, row := range rows {
		out[index] = plain(row)
	}
	return out
}
