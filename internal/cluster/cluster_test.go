package cluster_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"karma/internal/cluster"
	"karma/internal/model"
)

func TestParseEntryAndPath(t *testing.T) {
	row := "1759436000.123\t1759436000.123\t-rw-r--r-- 1 root root 220 Jan 01 10:00 /tmp/evil.sh"
	entry := cluster.ParseEntry(row)
	if entry == nil || cluster.EntryPath(entry) != "/tmp/evil.sh" {
		t.Fatalf("parse failed: %+v", entry)
	}
	if got := cluster.ParseEntry("garbage"); got != nil {
		t.Fatal("bad shape should return nil")
	}
}

func TestParseFindRow(t *testing.T) {
	row := "1759436000.5\t1759436000.5\t2025-10-03\t10:13:20.123456\t220\t/var/www/x.php"
	row0 := cluster.ParseFindRow(row)
	if row0 == nil {
		t.Fatal("should parse successfully")
	}
	if row0.Stamp != "2025-10-03 10:13:20" || row0.Nbytes != 220 || row0.Path != "/var/www/x.php" {
		t.Fatalf("wrong fields: %+v", row0)
	}
	if cluster.ParseFindRow("bad\trow") != nil {
		t.Fatal("bad shape returns nil")
	}
}

func TestOutlierMarkerAndMatch(t *testing.T) {
	now := time.Unix(1759436000, 0)
	nowSec := float64(now.Unix())
	if got := cluster.OutlierMarker(nowSec+3600, nowSec, false, now); got != "!!" {
		t.Fatalf("future time should be marked !!: %q", got)
	}
	if got := cluster.OutlierMarker(nowSec, nowSec, true, now); got != "!" {
		t.Fatalf("outlier should be marked !: %q", got)
	}
	if got := cluster.OutlierMarker(nowSec, nowSec, false, now); got != "" {
		t.Fatalf("normal line is unmarked: %q", got)
	}

	verdict := cluster.OutlierMatch("/tmp/.hidden", "!", 20)
	if verdict == nil || verdict.Severity != model.High || verdict.End != 20 {
		t.Fatalf("hidden file outlier should be high over the whole line: %+v", verdict)
	}
	if v := cluster.OutlierMatch("/tmp/x.sh", "!", 10); v == nil || v.Severity != model.Medium {
		t.Fatalf("script outlier should be medium: %+v", v)
	}
	if v := cluster.OutlierMatch("/tmp/x", "", 10); v != nil {
		t.Fatalf("no marker, no verdict: %+v", v)
	}
	if v := cluster.OutlierMatch("/tmp/x", "!!", 10); v == nil || v.Severity != model.Critical {
		t.Fatalf("timestamp anomaly is heaviest: %+v", v)
	}
}

// silence boundary: a small handful of files is 30 days from the main cluster; clustering should cut and mark them outliers.
func TestListingNormalizeMarksOutliers(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	var rows []string
	// main cluster: one install batch, 40 files spread one second apart
	for i := 0; i < 40; i++ {
		mtime := float64(base + int64(i))
		rows = append(rows, collectRow(mtime, mtime, "/srv/app/file"+strconv.Itoa(i)))
	}
	// outliers: two files landing 30 days later
	for i := 0; i < 2; i++ {
		mtime := float64(base + 30*86400 + int64(i))
		rows = append(rows, collectRow(mtime, mtime, "/tmp/.evil"+strconv.Itoa(i)))
	}
	normalize := cluster.ListingNormalize(func() time.Time { return time.Unix(base+31*86400, 0) })
	shaped := normalize("", strings.Join(rows, "\n"))
	if shaped == nil {
		t.Fatal("collection rows should produce a shaped result")
	}
	marked := 0
	for _, line := range strings.Split(shaped.Text, "\n") {
		// rows keep the bare ls shape: no leading marker, no gutter
		if !strings.HasPrefix(line, "-rw-r--r-- 1 root root 100 ") {
			t.Fatalf("collection rows carry no textual prefix: %q", line)
		}
		if strings.Contains(line, "/tmp/.evil") {
			marked++
		}
	}
	if marked != 2 {
		t.Fatalf("both outlier files should be flagged, got %d:\n%s", marked, shaped.Text)
	}
	if len(shaped.Notes) != 2 {
		t.Fatalf("outlier verdicts should become ranges at shaping time: %+v", shaped.Notes)
	}
}

// sparse small clusters with no dominant main cluster: stay quiet, no flooding.
func TestListingNormalizeQuietWithoutMainCluster(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	var rows []string
	for i := 0; i < 6; i++ {
		mtime := float64(base + int64(i)*8*86400) // six isolated files 8 days apart
		rows = append(rows, collectRow(mtime, mtime, "/srv/app/file"+strconv.Itoa(i)))
	}
	normalize := cluster.ListingNormalize(func() time.Time { return time.Unix(base+60*86400, 0) })
	shaped := normalize("", strings.Join(rows, "\n"))
	if len(shaped.Notes) != 0 {
		t.Fatalf("no dominant main cluster should stay quiet: %+v", shaped.Notes)
	}
}

// collectRow row shape: epoch mtime, epoch ctime, ls -l row shape (path trails).
func collectRow(mtime, ctime float64, path string) string {
	stamp := "Jan 01 00:00"
	return strconv.FormatFloat(mtime, 'f', 3, 64) + "\t" +
		strconv.FormatFloat(ctime, 'f', 3, 64) + "\t" +
		"-rw-r--r-- 1 root root 100 " + stamp + " " + path
}

// The listing normalizer lines the section's columns up and states its outlier
// verdict over the aligned line, which is the text the panel paints.
func TestListingNormalizeAlignsColumns(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	var rows []string
	for i := 0; i < 40; i++ {
		mtime := float64(base + int64(i))
		rows = append(rows, collectRow(mtime, mtime, "/srv/app/file"+strconv.Itoa(i)))
	}
	// one row of the section carries wider owner, group and size columns
	stamp := strconv.FormatFloat(float64(base+1), 'f', 3, 64)
	rows[1] = stamp + "\t" + stamp +
		"\t-rw-r--r-- 12 www-data www-data 1048576 Jan 01 00:00 /srv/app/file1"
	for i := 0; i < 2; i++ {
		mtime := float64(base + 30*86400 + int64(i))
		rows = append(rows, collectRow(mtime, mtime, "/tmp/.evil"+strconv.Itoa(i)))
	}

	normalize := cluster.ListingNormalize(func() time.Time { return time.Unix(base+31*86400, 0) })
	shaped := normalize("", strings.Join(rows, "\n"))
	if shaped == nil {
		t.Fatal("collection rows should produce a shaped result")
	}
	lines := strings.Split(shaped.Text, "\n")
	if len(lines) != len(rows) {
		t.Fatalf("one shaped line per row: %q", shaped.Text)
	}
	// every row's path starts in the same column
	pathColumn := -1
	for _, line := range lines {
		at := strings.LastIndex(line, " /")
		if at < 0 {
			t.Fatalf("no path in shaped row: %q", line)
		}
		if pathColumn < 0 {
			pathColumn = at
			continue
		}
		if at != pathColumn {
			t.Fatalf("paths do not line up: %d vs %d in\n%s", pathColumn, at, shaped.Text)
		}
	}
	if len(shaped.Notes) != 2 {
		t.Fatalf("the two outliers should be flagged: %+v", shaped.Notes)
	}
	for _, note := range shaped.Notes {
		if note.Match.End != len(lines[note.Line]) {
			t.Fatalf("a verdict covers the whole aligned line: %+v", note)
		}
	}
}
