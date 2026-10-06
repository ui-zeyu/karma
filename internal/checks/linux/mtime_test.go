package linux

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"karma/internal/model"
	"karma/internal/reader"
)

// findRow renders one find -printf collection row the way huntScript's format
// string does: mtime, ctime, date, clock, bytes, path, tab-separated.
func findRow(mtime float64, stamp string, nbytes int, path string) string {
	date, clock, _ := strings.Cut(stamp, " ")
	return fmt.Sprintf("%.6f\t%.6f\t%s\t%s\t%d\t%s", mtime, mtime, date, clock, nbytes, path)
}

// A lone file isolated from a big cluster is the outlier shape; the timeline leads
// and the outlier line carries its verdict as a span. The full listing stays out of
// the body — the evidence is one find away on the target.
func TestHuntNormalizeMarksOutliers(t *testing.T) {
	hunt := HuntCheck([]string{"/srv"})
	base := float64(time.Date(2023, 11, 14, 10, 20, 30, 0, time.UTC).Unix())
	var rows []string
	for i := 0; i < 10; i++ {
		rows = append(rows, findRow(base, "2023-11-14 10:20:30", 4096, fmt.Sprintf("/srv/app/log-%d", i)))
	}
	rows = append(rows, findRow(base+40*86400, "2023-12-24 10:20:30", 20480, "/srv/blob.bin"))
	text := strings.Join(rows, "\n")

	document := reader.Analyze(text, hunt.Rules, hunt.Filters, hunt.Normalize, 0, model.FloorAll)
	if len(document.Sections) != 1 {
		t.Fatalf("one section: %+v", document.Sections)
	}
	lines := document.Sections[0].Lines
	if strings.Contains(document.Sections[0].Lines[0].Text, "/srv/app/") {
		t.Fatalf("the main cluster's files should stay out of the body: %q", lines[0].Text)
	}
	var (
		marked  bool
		verdict model.Match
	)
	for _, line := range lines {
		if strings.Contains(line.Text, "/srv/blob.bin") {
			marked = true
			if !strings.HasPrefix(line.Text, "2023-12-24 10:20:30") {
				t.Fatalf("the outlier line carries no textual marker: %q", line.Text)
			}
			for _, match := range line.Matches {
				if match.ID == "mtime-outlier" {
					verdict = match
				}
			}
		}
	}
	if !marked {
		t.Fatalf("the isolated file should be printed as an outlier: %+v", document.Sections[0].Lines)
	}
	if verdict.ID != "mtime-outlier" || verdict.Severity != model.Low {
		t.Fatalf("the cluster verdict should grade the outlier line: %+v", verdict)
	}
}

func TestHuntNormalizeFlagsFutureTimestamp(t *testing.T) {
	hunt := HuntCheck([]string{"/srv"})
	future := float64(time.Now().Add(4000 * time.Second).Unix())
	text := findRow(future, "2099-01-01 00:00:00", 1, "/srv/forge.log")

	document := reader.Analyze(text, hunt.Rules, hunt.Filters, hunt.Normalize, 0, model.FloorAll)
	lines := document.Sections[0].Lines
	if !strings.HasPrefix(lines[len(lines)-1].Text, "2099-01-01") {
		t.Fatalf("the flagged line carries no textual marker: %q", lines[len(lines)-1].Text)
	}
	if len(lines[len(lines)-1].Matches) == 0 || lines[len(lines)-1].Matches[0].ID != "mtime-stamp-anomaly" {
		t.Fatalf("the anomaly should be stated as a span: %+v", lines[len(lines)-1].Matches)
	}
}
