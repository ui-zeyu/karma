// The listing checks under the reading pipeline: the two channels deliver the
// same row shape (find -printf over ssh, readdir + lstat in process) and the
// listing normalizer lines the columns up before the rules run, so the panel
// shows one aligned table and a hit's span covers the line it names.

package linux

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"karma/internal/model"
	"karma/internal/reader"
	"karma/internal/testkit"
)

// A section whose rows carry mixed column widths, in the shape the ssh tier's
// find prints (single spaces), with one hidden entry in a temp directory.
func listingBody(base int64) string {
	var body strings.Builder
	body.WriteString("== /tmp\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&body, "%d.000\t%d.000\t-rw-r--r-- 1 root root 100 Jan 01 00:00 /tmp/file%d\n",
			base+int64(i), base+int64(i), i)
	}
	// wider owner, group and size columns, and the hidden entry
	fmt.Fprintf(&body, "%d.000\t%d.000\t-rw-r--r-- 12 www-data www-data 1048576 Jan 01 00:00 /tmp/.backdoor\n",
		base+40, base+40)
	return body.String()
}

func TestTempListingAlignsRowsAndNamesTheHiddenEntry(t *testing.T) {
	check := testkit.CheckByID(t, All, "tmp-listing")
	base := time.Now().Add(-90 * 24 * time.Hour).Unix()
	body := listingBody(base)
	document := reader.Analyze(body, check.Rules, check.Filters, check.Normalize, 0)
	if len(document.Sections) != 1 {
		t.Fatalf("one section expected: %+v", document.Sections)
	}
	lines := document.Sections[0].Lines
	if len(lines) != 41 {
		t.Fatalf("every row should survive: %d", len(lines))
	}
	// One width for the whole listing: every row's path starts in one column.
	column := -1
	for _, line := range lines {
		at := strings.LastIndex(line.Text, " /tmp/")
		if at < 0 {
			t.Fatalf("no path in the row: %q", line.Text)
		}
		if column < 0 {
			column = at
			continue
		}
		if at != column {
			t.Fatalf("paths do not line up (%d vs %d):\n%s", column, at, joined(lines))
		}
	}
	// The hidden entry is named, and its span covers the path on the aligned row.
	for _, line := range lines {
		if !strings.Contains(line.Text, ".backdoor") {
			continue
		}
		named := false
		for _, match := range line.Matches {
			if match.ID == "hidden-tmp-path" && line.Text[match.Start:match.End] == "/tmp/.backdoor" {
				named = true
			}
		}
		if !named {
			t.Fatalf("the span should cover the path on the aligned row: %+v", line)
		}
	}
}

func joined(lines []model.Line) string {
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line.Text)
		b.WriteByte('\n')
	}
	return b.String()
}
