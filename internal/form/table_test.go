package form

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"karma/internal/model"
)

// The color assertions below read the escapes a form writes, so the profile is
// pinned: a test run has no terminal to ask.
func TestMain(m *testing.M) {
	lipgloss.SetColorProfile(termenv.ANSI256)
	os.Exit(m.Run())
}

// row is a record whose fields are the given name/value pairs.
func row(pairs ...string) *model.Record {
	rec := &model.Record{}
	for index := 0; index+1 < len(pairs); index += 2 {
		rec.Fields = append(rec.Fields, model.Field{Name: pairs[index], Value: pairs[index+1]})
	}
	return rec
}

// hit is a match located in a field, the way a rule states it.
func hit(id string, severity model.Severity, message string, field, start, end int) model.Match {
	return model.Match{ID: id, Severity: severity, Message: message,
		Spans: []model.Span{{Field: field, Start: start, End: end}}}
}

func render(t *testing.T, table Table, block model.Block, width int, color bool) []string {
	t.Helper()
	return table.Render(block, model.RenderOptions{Width: width, Color: color})
}

// The table puts the column names over their columns, one row per record, and
// pads the cells the way each column asks: numbers end at their right edge, the
// last column keeps what it wrote (nothing follows the row's own text).
func TestTableRendersHeadAndRows(t *testing.T) {
	table := Table{Align: map[string]Alignment{"PID": Right}}
	block := model.Block{
		Header: []string{"USER", "PID", "COMMAND"},
		Items: []model.BlockItem{
			{Rec: row("USER", "root", "PID", "1", "COMMAND", "/sbin/init")},
			{Rec: row("USER", "www-data", "PID", "2210", "COMMAND", "/bin/sh")},
		},
	}
	lines := render(t, table, block, 40, false)
	if len(lines) != 3 {
		t.Fatalf("heads and rows = %d lines, want 3: %q", len(lines), lines)
	}
	// The head and the row carry their cells in column order, two blanks apart.
	for _, want := range []string{"USER", "PID", "COMMAND"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("the head should carry %q: %q", want, lines[0])
		}
	}
	for _, want := range []string{"root", "1", "/sbin/init"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("the row should carry %q: %q", want, lines[1])
		}
	}
	if strings.Index(lines[0], "USER") > strings.Index(lines[0], "PID") {
		t.Errorf("the head should keep the column order: %q", lines[0])
	}
	// The numbers end at the column's right edge, so a one-digit pid still ends
	// under the heading's last character.
	pid := strings.Index(lines[0], "PID")
	if at := strings.Index(lines[1], "1"); at+1 != pid+len("PID") {
		t.Errorf("PID should be right-aligned:\n%q\n%q", lines[0], lines[1])
	}
	// The row ends with the last cell itself: no padding and no trailing blanks.
	if lines[1] != strings.TrimRight(lines[1], " ") {
		t.Errorf("the last column should not be padded: %q", lines[1])
	}
}

// A rule that states its hit in a field paints that field, and only the bytes it
// named: the rest of the cell keeps the column's own tint.
func TestTablePaintsTheBytesTheHitNamed(t *testing.T) {
	table := Table{}
	rec := row("USER", "root", "COMMAND", "/usr/bin/x /tmp/p")
	block := model.Block{
		Header: []string{"USER", "COMMAND"},
		Items: []model.BlockItem{{
			Rec:     rec,
			Matches: []model.Match{hit("tmp-path", model.Medium, "temp path", 1, 11, 17)},
		}},
	}
	painted := render(t, table, block, 60, true)
	if len(painted) != 3 {
		t.Fatalf("lines = %q", painted)
	}
	medium := SeverityPaint(model.Medium).Style()
	if !strings.Contains(painted[1], medium.Render("/tmp/p")) {
		t.Errorf("the hit's bytes should carry the severity color: %q", painted[1])
	}
	if strings.Contains(painted[1], medium.Render("/usr/bin/x")) {
		t.Errorf("the rest of the cell should keep the column's tint: %q", painted[1])
	}
	// Without color the same table is the plain text, aligned the same way.
	plainLines := render(t, table, block, 60, false)
	if strings.Contains(strings.Join(plainLines, "\n"), "\x1b") {
		t.Errorf("a table without color should carry no escapes: %q", plainLines)
	}
	if !strings.Contains(plainLines[1], "/tmp/p") {
		t.Errorf("the plain table should carry the value: %q", plainLines[1])
	}
}

// A hit that named two fields paints both of them and only them: the account
// cell at one end, the word the pattern matched at the other, with the columns
// between them untouched.
func TestTablePaintsEachSpanInItsOwnCell(t *testing.T) {
	table := Table{}
	rec := row("USER", "www-data", "PID", "2210", "COMMAND", "/bin/sh -c id")
	block := model.Block{
		Header: []string{"USER", "PID", "COMMAND"},
		Items: []model.BlockItem{{
			Rec: rec,
			Matches: []model.Match{{
				ID: "service-shell", Severity: model.High, Message: "service account with a shell",
				Spans: []model.Span{
					{Field: 0, Start: 0, End: len("www-data")},
					{Field: 2, Start: 0, End: len("/bin/sh")},
				},
			}},
		}},
	}
	painted := render(t, table, block, 60, true)
	high := SeverityPaint(model.High).Style()
	if !strings.Contains(painted[1], high.Render("www-data")) {
		t.Errorf("the account cell the rule named should be painted: %q", painted[1])
	}
	if !strings.Contains(painted[1], high.Render("/bin/sh")) {
		t.Errorf("the word the pattern matched should be painted: %q", painted[1])
	}
	if strings.Contains(painted[1], high.Render("2210")) {
		t.Errorf("a column between the two spans keeps its own tint: %q", painted[1])
	}
	if strings.Contains(painted[1], high.Render("-c id")) {
		t.Errorf("the hit should stop at the word the pattern matched: %q", painted[1])
	}
}

// A hit with no span belongs to the record itself, and the row carries it
// whole: the finding is the row, and no cell of it stands for the finding.
func TestTablePaintsARecordHitWholeRow(t *testing.T) {
	table := Table{}
	block := model.Block{
		Header: []string{"USER", "PID", "COMMAND"},
		Items: []model.BlockItem{{
			Rec: row("USER", "www-data", "PID", "2210", "COMMAND", "/bin/sh"),
			Matches: []model.Match{{
				ID: "service-shell", Severity: model.High, Message: "service account with a shell",
			}},
		}},
	}
	painted := render(t, table, block, 60, true)
	high := SeverityPaint(model.High).Style()
	for _, want := range []string{"www-data", "2210", "/bin/sh"} {
		if !strings.Contains(painted[1], high.Render(want)) {
			t.Errorf("the whole row should carry the hit, %q did not: %q", want, painted[1])
		}
	}
}

// The reason a hit states is said under the column the hit fell in: the row
// keeps its own shape, and the explanation sits beside the field it names.
func TestTableSaysTheReasonUnderItsColumn(t *testing.T) {
	table := Table{}
	block := model.Block{
		Header: []string{"USER", "COMMAND"},
		Items: []model.BlockItem{{
			Rec:     row("USER", "root", "COMMAND", "/tmp/x"),
			Matches: []model.Match{hit("tmp-path", model.Medium, "temp path", 1, 0, 6)},
		}},
	}
	lines := render(t, table, block, 60, false)
	if len(lines) != 3 || lines[1] != "root  /tmp/x" {
		t.Fatalf("the row should be the head and one line: %q", lines)
	}
	// USER is four cells and the gap two, so the reason sits under the command
	// column.
	if lines[2] != "      ⟨temp path⟩" {
		t.Errorf("the reason should sit under its column: %q", lines[2])
	}
}

// A counted gap the display budget left is a structural row of its own: it is
// printed where it falls and takes no column.
func TestTableKeepsTheCallersNoteInPlace(t *testing.T) {
	table := Table{}
	block := model.Block{
		Header: []string{"USER", "PID"},
		Items: []model.BlockItem{
			{Rec: row("USER", "root", "PID", "1")},
			{Note: "… 12 lines"},
			{Rec: row("USER", "root", "PID", "2")},
		},
	}
	lines := render(t, table, block, 40, false)
	if len(lines) != 4 || lines[2] != "… 12 lines" {
		t.Fatalf("the note should stand where it was put: %q", lines)
	}
}

// The panel's width decides the columns: the last one takes what is left, and
// a value too wide for it wraps inside it — the row grows lines, the
// continuation sits under the column it belongs to, and every line fits the
// panel. A token with no blank in it is broken hard at the column's width.
func TestTableWrapsTheWideColumn(t *testing.T) {
	table := Table{}
	value := strings.Repeat("/very/long", 10)
	rec := row("USER", "root", "COMMAND", value)
	block := model.Block{Header: []string{"USER", "COMMAND"}, Items: []model.BlockItem{{Rec: rec}}}
	lines := render(t, table, block, 40, false)
	if len(lines) != 4 { // the head and the row's three lines
		t.Fatalf("the wide value should wrap, got %q", lines)
	}
	if lines[1] != "root  "+value[:34] {
		t.Errorf("the first line should carry the head of the value: %q", lines[1])
	}
	// USER is four cells and the gap two, so the continuation starts six cells
	// in — under the command column.
	if lines[2] != "      "+value[34:68] || lines[3] != "      "+value[68:] {
		t.Errorf("the continuation should sit under its column: %q / %q", lines[2], lines[3])
	}
	if strings.Contains(strings.Join(lines, "\n"), "…") {
		t.Errorf("the last column wraps rather than being cut: %q", lines)
	}
}

// The wrap breaks at a blank when one falls inside the line, so a command line
// keeps its words.
func TestTableWrapsAtBlanks(t *testing.T) {
	table := Table{}
	rec := row("USER", "root", "COMMAND", "/usr/sbin/sshd -D -o ListenAddress=0.0.0.0")
	block := model.Block{Header: []string{"USER", "COMMAND"}, Items: []model.BlockItem{{Rec: rec}}}
	lines := render(t, table, block, 40, false)
	if len(lines) != 3 {
		t.Fatalf("the value should wrap at its blank, got %q", lines)
	}
	if lines[1] != "root  /usr/sbin/sshd -D -o" {
		t.Errorf("the first line should end at the last word that fits: %q", lines[1])
	}
	if lines[2] != "      ListenAddress=0.0.0.0" {
		t.Errorf("the continuation should start with the word the break pushed down: %q", lines[2])
	}
}

// Every column wraps, and a row's lines stay aligned: each continuation sits
// under its own column, and a column a line does not reach is blank there. The
// head wraps like a value, so a squeezed column's name is whole too.
func TestTableWrapsEveryColumn(t *testing.T) {
	rec := row("USER", "www-data", "PID", "2210", "TTY", "?", "COMMAND", "/usr/bin/x")
	block := model.Block{Header: []string{"USER", "PID", "TTY", "COMMAND"}, Items: []model.BlockItem{{Rec: rec}}}
	lines := render(t, Table{}, block, 24, false)
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"www-dat", "a", "/usr", "/bin", "/x", "COMM", "AND"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the wrap should print %q whole, over as many lines as it takes:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "…") {
		t.Errorf("nothing should be cut:\n%s", joined)
	}
	for _, line := range lines {
		if got := lipgloss.Width(line); got > 24 {
			t.Errorf("a line should fit the panel (24): %d %q", got, line)
		}
	}
	// The user column's continuation sits under the user column, the command's
	// under its own: the row's lines stay a grid.
	if lines[len(lines)-2] != "a                   /bin" {
		t.Errorf("the continuations should sit under their own columns: %q", lines[len(lines)-2])
	}
}

// A hit keeps its bytes through the wrap: the span lands on the line that
// shows those bytes, cut to the part that line holds.
func TestTablePaintsHitsThroughTheWrap(t *testing.T) {
	table := Table{}
	rec := row("USER", "root", "COMMAND", "/bin/sh -c /tmp/passwordx")
	block := model.Block{
		Header: []string{"USER", "COMMAND"},
		Items: []model.BlockItem{{
			Rec:     rec,
			Matches: []model.Match{hit("tmp-path", model.Medium, "temp path", 1, 16, 25)},
		}},
	}
	painted := render(t, table, block, 30, true)
	medium := SeverityPaint(model.Medium).Style()
	if !strings.Contains(painted[2], medium.Render("passwordx")) {
		t.Errorf("the hit should paint on the line that shows its bytes: %q", painted[2])
	}
	if strings.Contains(painted[1], medium.Render("/bin/sh")) {
		t.Errorf("the first line holds none of the hit's bytes: %q", painted[1])
	}
}

// A column's tint comes from the cycle by position, or from the declaration by
// name; the last column stays plain unless it asks for a color, because that is
// where the wide value runs to the edge.
func TestTableTintsColumns(t *testing.T) {
	painted := strings.Join(render(t, Table{}, model.Block{
		Header: []string{"USER", "STAT", "COMMAND"},
		Items:  []model.BlockItem{{Rec: row("USER", "root", "STAT", "Ss", "COMMAND", "bash")}},
	}, 40, true), "\n")
	if !strings.Contains(painted, ColumnPaint(0).Style().Render("root")) {
		t.Errorf("the first column should take the cycle's first tint: %q", painted)
	}
	if !strings.Contains(painted, ColumnPaint(1).Style().Render("Ss")) {
		t.Errorf("the second column should take the cycle's second tint: %q", painted)
	}
	if strings.Contains(painted, ColumnPaint(2).Style().Render("bash")) {
		t.Errorf("the last column should stay plain: %q", painted)
	}
	declared := strings.Join(render(t, Table{Tint: map[string]Tint{"COMMAND": 4}}, model.Block{
		Header: []string{"USER", "COMMAND"},
		Items:  []model.BlockItem{{Rec: row("USER", "root", "COMMAND", "bash")}},
	}, 40, true), "\n")
	if !strings.Contains(declared, ColumnPaint(4).Style().Render("bash")) {
		t.Errorf("a column that names a tint should take it: %q", declared)
	}
}

// A regexp-valued predicate and a pattern rule state the same kind of hit, so
// the table paints them the same way.
func TestTablePaintsAFieldRegexHit(t *testing.T) {
	rule := model.NewJudged("http-server", model.Medium, "python http server",
		model.FieldRegex{Fields: []string{"COMMAND"}, Pattern: regexp.MustCompile(`-m\s+http\.server`)})
	rec := row("USER", "www-data", "COMMAND", "python3 -m http.server 8080")
	matches := rule.Judge(rec)
	lines := render(t, Table{}, model.Block{
		Header: []string{"USER", "COMMAND"},
		Items:  []model.BlockItem{{Rec: rec, Matches: matches}},
	}, 60, true)
	if len(matches) != 1 {
		t.Fatalf("the rule should state one hit: %+v", matches)
	}
	medium := SeverityPaint(model.Medium).Style()
	if !strings.Contains(lines[1], medium.Render("-m http.server")) {
		t.Errorf("the matched bytes should be painted: %q", lines[1])
	}
	// The user column is eight cells (www-data) and the gap two, so the
	// reason sits under the command column.
	if lines[2] != "          "+DimPaint().Style().Render("⟨python http server⟩") {
		t.Errorf("the reason should hang under the column: %q", lines[2])
	}
}
