// The access-log summary is one in-process pass over each log file's tail; these
// tests pin the tables it prints and the rows it keeps.

package linux

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"karma/internal/checks/linux/native"
	"karma/internal/model"
	"karma/internal/reader"
	"karma/internal/testkit"
)

// accessLogFixture is one Apache combined log: a scanner, a traversal, a
// command parameter and a config probe among ordinary requests.
var accessLogFixture = []string{
	`192.168.17.21 - - [18/Apr/2024:02:34:01 +0800] "GET /index.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`,
	`192.168.17.21 - - [18/Apr/2024:02:34:02 +0800] "GET /admin.php HTTP/1.1" 404 123 "-" "sqlmap/1.7"`,
	`192.168.17.21 - - [18/Apr/2024:02:34:03 +0800] "POST /upload.php HTTP/1.1" 200 12 "-" "curl/8.0"`,
	`192.168.17.21 - - [18/Apr/2024:02:35:10 +0800] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" "Mozilla/5.0"`,
	`10.0.0.9 - - [18/Apr/2024:02:35:11 +0800] "GET /index.php?cmd=whoami HTTP/1.1" 200 3 "-" "Mozilla/5.0"`,
	`10.0.0.9 - - [18/Apr/2024:02:36:00 +0800] "GET /.env HTTP/1.1" 404 0 "-" "Mozilla/5.0"`,
	`10.0.0.9 - - [18/Apr/2024:02:37:00 +0800] "GET /assets/team-4.jpg HTTP/1.1" 200 4096 "-" "Mozilla/5.0"`,
}

func TestAccessLogSummaryTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, []byte(strings.Join(accessLogFixture, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The tables are the context and the four request lines are the findings:
	// an ordinary request is counted and never listed.
	want := "clients\n" +
		"     4 192.168.17.21\n" +
		"     3 10.0.0.9\n" +
		"minutes\n" +
		"     3 18/Apr/2024:02:34\n" +
		"     2 18/Apr/2024:02:35\n" +
		"     1 18/Apr/2024:02:36\n" +
		"     1 18/Apr/2024:02:37\n" +
		"requests\n" +
		accessLogFixture[1] + "\n" + accessLogFixture[3] + "\n" +
		accessLogFixture[4] + "\n" + accessLogFixture[5] + "\n"

	body, err := native.AccessLogFile(path, accessLogKeepRe)(context.Background())
	if err != nil {
		t.Fatalf("the tier failed: %v", err)
	}
	if body != want {
		t.Errorf("the tier reported\n%q\nwant\n%q", body, want)
	}
}

// A log that holds nothing — empty, or not there — leaves no section behind:
// the check reports what it read, and an absent file is not an empty one.
func TestAccessLogBodySkipsEmptyAndAbsentFiles(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(empty, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(t.TempDir(), "access.log")
	for _, path := range []string{empty, absent} {
		body, err := native.AccessLogFile(path, accessLogKeepRe)(context.Background())
		if err != nil {
			t.Fatalf("the local tier failed: %v", err)
		}
		if body != "" {
			t.Errorf("%s rendered %q, want nothing", path, body)
		}
	}
}

// The summary's own tables are context; the request lines it carries are graded
// by the four rules the keep pattern is built from, each painting the token its
// reason names.
func TestAccessLogGradesRequestLines(t *testing.T) {
	check := testkit.CheckByID(t, All, "access-log")
	cases := []struct {
		line     string
		severity string
		rule     string
		span     string
	}{
		{accessLogFixture[1], "high", "log-scan-tool", "sqlmap"},
		{accessLogFixture[3], "high", "log-traversal", `../../`},
		{accessLogFixture[4], "high", "log-exec-param", "?cmd="},
		{accessLogFixture[5], "medium", "log-sensitive-file", ".env"},
	}
	for _, tc := range cases {
		document := reader.Analyze(tc.line, check.Rules, check.Filters, 0, model.FloorAll, check.Normalize)
		line := document.Sections[0].Lines[0]
		if got := line.Severity.String(); got != tc.severity {
			t.Errorf("%q should be graded %s, got %s", tc.line, tc.severity, got)
		}
		var spans []string
		for _, match := range line.Matches {
			if match.ID != tc.rule {
				continue
			}
			// A body of text is a one-field record, so the spans sit in the
			// line's own coordinates.
			for _, span := range match.Spans {
				spans = append(spans, line.Text[span.Start:span.End])
			}
		}
		if !slices.Contains(spans, tc.span) {
			t.Errorf("%s paints %v on %q, want %q", tc.rule, spans, tc.line, tc.span)
		}
	}
}

// The keep pattern and the rules are one vocabulary: every arm of the pattern
// has a rule that explains it, so a request line the pipeline keeps never
// reaches the panel without a reason.
func TestAccessLogKeepAndRulesAreOneVocabulary(t *testing.T) {
	check := testkit.CheckByID(t, All, "access-log")
	kept := []struct{ line, rule string }{
		{`1.2.3.4 - - [18/Apr/2024:02:34:02 +0800] "GET /a HTTP/1.1" 404 1 "-" "nuclei 3.0"`, "log-scan-tool"},
		{`1.2.3.4 - - [18/Apr/2024:02:34:02 +0800] "GET /x?a=%2e%2e/b HTTP/1.1" 400 0`, "log-traversal"},
		{`1.2.3.4 - - [18/Apr/2024:02:34:02 +0800] "GET /x?upload=1 HTTP/1.1" 200 0`, "log-exec-param"},
		{`1.2.3.4 - - [18/Apr/2024:02:34:02 +0800] "GET /backup.tar.gz HTTP/1.1" 404 0`, "log-sensitive-file"},
		{`1.2.3.4 - - [18/Apr/2024:02:34:02 +0800] "GET /.git/config HTTP/1.1" 404 0`, "log-sensitive-file"},
		{`1.2.3.4 - - [18/Apr/2024:02:34:02 +0800] "GET /phpmyadmin/ HTTP/1.1" 404 0`, "log-sensitive-file"},
	}
	for _, tc := range kept {
		if !accessLogKeepRe.MatchString(tc.line) {
			t.Errorf("the keep pattern does not cover %q", tc.line)
		}
		if !slices.Contains(testkit.HitIDs(t, tc.line, check), tc.rule) {
			t.Errorf("%q should light %s, got %v", tc.line, tc.rule, testkit.HitIDs(t, tc.line, check))
		}
	}
	// and an ordinary request is neither kept nor graded
	for _, line := range []string{accessLogFixture[0], accessLogFixture[2], accessLogFixture[6]} {
		if accessLogKeepRe.MatchString(line) {
			t.Errorf("an ordinary request was kept: %q", line)
		}
	}
}
