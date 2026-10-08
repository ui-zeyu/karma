// df under the reading pipeline: the two sources print the same table, and the
// reading turns either one into the records the check's form draws — so the
// panel lays the numbers out itself and no lexer re-splits the tool's spacing.

package linux

import (
	"slices"
	"strings"
	"testing"

	"karma/internal/shape"
	"karma/internal/testkit"
)

// df's body is a table, and the reading hands the check's form the records it
// draws: the columns come from the shaped table, every line carries its own
// record, and the header line is the form's rather than a row of the body.
func TestDfHandsTheFormItsRecords(t *testing.T) {
	check := testkit.CheckByID(t, All, "df")
	body := "Filesystem      Size  Used Avail Use% Mounted on\n" +
		"/dev/vda1        40G   15G   25G  38% /\n" +
		"tmpfs           391M     0  391M   0% /dev/shm\n"
	document := readOneSection(check, "", body)
	if len(document.Sections) != 1 {
		t.Fatalf("one section expected: %+v", document.Sections)
	}
	section := document.Sections[0]
	if !slices.Equal(section.Columns, shape.DfColumns) {
		t.Fatalf("columns = %v, want df's table %v", section.Columns, shape.DfColumns)
	}
	if len(section.Lines) != 2 {
		t.Fatalf("the rows are the lines and the header is not: %+v", section.Lines)
	}
	for _, line := range section.Lines {
		if line.Record == nil {
			t.Fatalf("every line carries its record: %q", line.Text)
		}
	}
	if strings.Contains(section.Lines[0].Text, "Filesystem") {
		t.Fatalf("the header should not be a body line: %q", section.Lines[0].Text)
	}
}

// A body that is not df's table reaches the panel as the tool wrote it: the
// shaper declines it, and the section keeps every line with no columns to draw
// a form from.
func TestDfKeepsABodyItCannotRead(t *testing.T) {
	check := testkit.CheckByID(t, All, "df")
	body := "Filesystem  Type  Size  Used  Avail  Use%\n/dev/vda1 ext4 40G 15G 25G 38%\n"
	document := readOneSection(check, "", body)
	if len(document.Sections) != 1 || len(document.Sections[0].Lines) != 2 {
		t.Fatalf("the whole body should stay: %+v", document.Sections)
	}
	if columns := document.Sections[0].Columns; len(columns) != 0 {
		t.Fatalf("a declined body has no columns: %v", columns)
	}
}
