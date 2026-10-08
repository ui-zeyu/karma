// The process panel: a check whose tier reads fields, drawn in the table the
// check declares. The fixture is the record set the ps tier answers with, so
// this walks the whole path the report takes: the collection's fields, the
// reading pipeline's judgment, and the form's layout.

package render

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"karma/internal/checks"
	"karma/internal/checks/linux/native"
	"karma/internal/model"
	"karma/internal/testkit"
)

// psPanel is the ps check's result over the given rows; each row is written as
// the values of the columns it overrides, so a fixture states only what its
// case is about. The columns are the tier's own schema: `ps -ef`'s System V
// eight, which both sources state.
func psPanel(t *testing.T, rows ...map[string]string) *model.CheckResult {
	t.Helper()
	check := psCheck(t)
	set := model.RecordSet{Header: native.PsEfColumns}
	for _, overrides := range rows {
		values := map[string]string{
			"UID": "root", "PID": "1", "PPID": "0", "C": "0", "STIME": "Sep30", "TTY": "?",
			"TIME": "00:00:03", "CMD": "/sbin/init",
		}
		for name, value := range overrides {
			values[name] = value
		}
		record := model.Record{}
		for _, name := range native.PsEfColumns {
			record.Fields = append(record.Fields, model.Field{Name: name, Value: values[name]})
		}
		set.Rows = append(set.Rows, record)
	}
	return &model.CheckResult{
		Check: check, Outcome: model.Collected, ProbeLabel: "ps",
		Raw:      model.RecordsText(set.Rows),
		Records:  &set,
		Document: testkit.RecordsDocument(&set, check),
	}
}

// psCheck is the catalog's ps check.
func psCheck(t *testing.T) *model.Check {
	t.Helper()
	return checkByID(t, "ps")
}

// checkByID is the Linux catalog check with this id.
func checkByID(t *testing.T, id string) *model.Check {
	t.Helper()
	for _, check := range checks.ChecksFor(model.Linux) {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("the Linux catalog has no %s check", id)
	return nil
}

// pstreePanel is the pstree check's result over the given processes, each one
// as its pid, ppid and command line: the same path the report walks — the
// tier's fields, the reading layer's judgment, and the tree form's layout.
func pstreePanel(t *testing.T, procs ...[3]string) *model.CheckResult {
	t.Helper()
	check := checkByID(t, "pstree")
	set := model.RecordSet{Header: native.PsEfColumns}
	for _, proc := range procs {
		values := map[string]string{
			"UID": "root", "PID": proc[0], "PPID": proc[1], "C": "0", "STIME": "Sep30",
			"TTY": "?", "TIME": "00:00:00", "CMD": proc[2],
		}
		record := model.Record{}
		for _, name := range native.PsEfColumns {
			record.Fields = append(record.Fields, model.Field{Name: name, Value: values[name]})
		}
		set.Rows = append(set.Rows, record)
	}
	return &model.CheckResult{
		Check: check, Outcome: model.Collected, ProbeLabel: "pstree",
		Raw:      model.RecordsText(set.Rows),
		Records:  &set,
		Document: testkit.RecordsDocument(&set, check),
	}
}

// The parent link a tier handed over is what the panel draws: the same kind of
// body the ps table lays in columns comes out as a nest, and the tree prints no
// column head at all.
func TestPstreePanelIsANest(t *testing.T) {
	result := pstreePanel(t,
		[3]string{"2210", "948", "-bash"},
		[3]string{"1", "0", "/sbin/init"},
		[3]string{"948", "1", "/usr/sbin/sshd -D"},
	)
	panel := plain(checkPanel(result, 400, 100, true))
	if strings.Contains(panel, "PPID") {
		t.Errorf("the tree should draw no column head:\n%s", panel)
	}
	for _, want := range []string{
		"1 /sbin/init",
		"└── 948 /usr/sbin/sshd -D",
		"    └── 2210 -bash",
	} {
		if !strings.Contains(panel, want) {
			t.Errorf("the panel should carry %q:\n%s", want, panel)
		}
	}
}

// A finding lands on the node it was judged on: the bytes a pattern rule named
// are painted inside the node, and the reason ends its line.
func TestPstreePanelPaintsTheNodeThatMatched(t *testing.T) {
	result := pstreePanel(t,
		[3]string{"1", "0", "/sbin/init"},
		[3]string{"2210", "1", "/tmp/x"},
	)
	painted := checkPanel(result, 400, 100, true)
	if !strings.Contains(plain(painted), "⟨command line references temp path⟩") {
		t.Errorf("the node should carry its reason:\n%s", plain(painted))
	}
	medium := severityStyle(model.Medium)
	node := rowWith(painted, "2210")
	if !strings.Contains(node, medium.Style().Render("/tmp/x")) {
		t.Errorf("the matched bytes should be painted on the node:\n%q", node)
	}
	if strings.Contains(rowWith(painted, "/sbin/init"), medium.Style().Render("/sbin/init")) {
		t.Errorf("a quiet node should stay plain:\n%q", rowWith(painted, "/sbin/init"))
	}
}

// The panel is a table: the tier's column names across the top, one row per
// process, the numeric columns ending at their column's right edge, and the
// command line taking whatever the panel has left.
func TestProcessPanelIsATable(t *testing.T) {
	result := psPanel(t, nil, map[string]string{"UID": "www-data", "PID": "2210", "C": "3", "CMD": "/bin/sh"})
	panel := plain(checkPanel(result, 400, 100, true))

	head := rowCarrying(panel, "UID")
	if head == "" {
		t.Fatalf("the panel should carry the table's head:\n%s", panel)
	}
	// The head is the record set's own column order (each name searched for
	// past the one before it: TIME sits inside STIME).
	previous := 0
	for _, name := range native.PsEfColumns {
		at := strings.Index(head[previous:], name)
		if at < 0 {
			t.Errorf("the head should carry %s in order: %q", name, head)
			break
		}
		previous += at
	}
	// Every row's values are on the panel, and the numeric columns end at their
	// own right edge.
	busy := rowCarrying(panel, "2210")
	for _, want := range []string{"www-data", "2210", "00:00:03", "/bin/sh"} {
		if !strings.Contains(busy, want) {
			t.Errorf("the row should carry %q: %q", want, busy)
		}
	}
	if at := strings.Index(busy, "2210"); at+len("2210") != strings.Index(head, "PID")+len("PID") {
		t.Errorf("PID should be right-aligned under its heading:\n%q\n%q", head, busy)
	}
}

// A rule that names two fields paints both of them and only them: the account
// cell at one end, the interpreter word the pattern matched at the other, the
// columns between them and the command line's own arguments untouched.
func TestProcessPanelPaintsTheFieldsTheRuleNamed(t *testing.T) {
	result := psPanel(t, map[string]string{"UID": "www-data", "PID": "2210", "CMD": "/bin/sh -c id"})
	painted := checkPanel(result, 400, 100, true)
	if !strings.Contains(painted, "⟨service account running a shell/interpreter") {
		t.Errorf("the row should carry its reason:\n%s", plain(painted))
	}
	medium := severityStyle(model.Medium)
	row := rowWith(painted, "2210")
	if !strings.Contains(row, medium.Style().Render("www-data")) {
		t.Errorf("the account field the rule named should be painted:\n%q", row)
	}
	if !strings.Contains(row, medium.Style().Render("sh")) {
		t.Errorf("the interpreter word the pattern matched should be painted:\n%q", row)
	}
	if strings.Contains(row, medium.Style().Render("2210")) {
		t.Errorf("a column between the two fields keeps its own color:\n%q", row)
	}
	if !strings.Contains(plain(row), "-c id") {
		t.Errorf("the command line's arguments should still be printed:\n%q", row)
	}
	if strings.Contains(row, medium.Style().Render("-c id")) {
		t.Errorf("the hit should stop at the word the pattern matched:\n%q", row)
	}
	// The same row read from a text body instead of a record: a field-shaped
	// rule has no column to speak about, so it stays quiet rather than guessing.
	const asText = "www-data 2210 0.0 0.1 22452 9120 ? Ss Sep30 0:03 /bin/sh\n"
	plainRow := checkPanel(&model.CheckResult{
		Check: result.Check, Outcome: model.Collected, ProbeLabel: "ps",
		Raw:      asText,
		Document: testkit.Analyze(asText, result.Check),
	}, 400, 100, true)
	if strings.Contains(plainRow, "⟨") {
		t.Errorf("a field rule should stay quiet on a body with no fields:\n%s", plain(plainRow))
	}
}

// Off a terminal the table is printed with no escapes and no trailing blanks: a
// redirected report reads as the aligned table it is. (The panel's rail and
// headings are painted by the panel's own pass, which is where the same flag
// reaches next.)
func TestProcessTableIsPlainOffATerminal(t *testing.T) {
	result := psPanel(t, map[string]string{"PID": "2210", "CMD": "/bin/sh -c id"})
	panel := checkPanel(result, 400, 100, false)
	for _, want := range []string{"UID", "2210", "/bin/sh -c id"} {
		row := rowWith(panel, want)
		if row == "" {
			t.Fatalf("the plain table should still carry %q:\n%s", want, panel)
		}
		// Past the rail, which is the panel's own paint.
		table := strings.TrimPrefix(strings.SplitN(row, "▌", 2)[1], "\x1b[0m")
		if strings.Contains(table, "\x1b") {
			t.Errorf("a table row without color should carry no escapes: %q", table)
		}
		if table != strings.TrimRight(table, " ") {
			t.Errorf("no row should end in padding: %q", table)
		}
	}
}

// On a panel the table cannot fit, every column gives way and every cell
// wraps: nothing is cut anywhere — the table grows down instead.
func TestProcessTableWrapsOnANarrowPanel(t *testing.T) {
	long := strings.Repeat("/very/long/path", 12)
	result := psPanel(t, map[string]string{"CMD": long})
	const width = 60
	panel := checkPanel(result, 400, width, true)
	body := plain(panel)
	for _, line := range strings.Split(body, "\n") {
		if got := lipgloss.Width(line); got > width {
			t.Errorf("no line may reach past the panel's width (%d): %d %q", width, got, line)
		}
	}
	if strings.Contains(body, "…") {
		t.Errorf("no value may be cut:\n%s", body)
	}
}

// A panel with room for the table wraps the command column inside its width:
// the whole command line is printed, no line reaches past the panel, and the
// value spans as many lines as its column is narrow for.
func TestProcessTableWrapsToThePanel(t *testing.T) {
	long := strings.Repeat("/very/long/path", 12)
	result := psPanel(t, map[string]string{"CMD": long})
	const width = 100
	panel := checkPanel(result, 400, width, true)
	body := plain(panel)
	for _, line := range strings.Split(body, "\n") {
		if got := lipgloss.Width(line); got > width {
			t.Errorf("no line may reach past the panel's width (%d): %d %q", width, got, line)
		}
	}
	if strings.Contains(body, "…") {
		t.Errorf("a panel with room for the table should cut nothing:\n%s", body)
	}
	tail := long[len(long)-20:]
	if !strings.Contains(body, tail) {
		t.Errorf("the whole command line should be printed, tail %q missing:\n%s", tail, body)
	}
	if strings.Contains(body, long) {
		t.Errorf("a wrapped value spans lines, so no one line holds it whole:\n%s", body)
	}
}

// rowCarrying is the first line of a panel carrying want; "" when none does.
func rowCarrying(panel, want string) string {
	for _, line := range strings.Split(panel, "\n") {
		if strings.Contains(line, want) {
			return line
		}
	}
	return ""
}

// rowWith is the first line of a painted panel carrying want.
func rowWith(panel, want string) string { return rowCarrying(panel, want) }
