package linux

import (
	"strings"
	"testing"

	"karma/internal/model"
)

// collapseRepeats folds consecutive duplicate log lines into one `[xN]` line; the
// collapse key erases the always-changing bits (timestamp, pid, port) so only the
// body has to be identical.
func TestCollapseRepeats(t *testing.T) {
	text := strings.Join([]string{
		"Jun  1 10:20:01 web CRON[1234]: pam_unix cron session for user root",
		"Jun  1 10:21:01 web CRON[2345]: pam_unix cron session for user root",
		"Jun  1 10:22:01 web sshd[111]: Accepted password for root from 10.0.0.8 port 5555 ssh2",
	}, "\n")
	shaped := collapseRepeats("", text)
	lines := strings.Split(shaped.Text, "\n")
	if len(lines) != 2 {
		t.Fatalf("two runs should remain: %q", shaped.Text)
	}
	if !strings.HasSuffix(lines[0], "session for user root [x2]") {
		t.Fatalf("the duplicate pair should collapse into [x2]: %q", lines[0])
	}
	if !strings.Contains(lines[1], "Accepted password") {
		t.Fatalf("the distinct line should stay verbatim: %q", lines[1])
	}
}

// The key erases the first syslog timestamp and the pid/port so near-duplicates
// count as one run.
func TestCollapseKey(t *testing.T) {
	first := collapseKey("Jun  1 10:20:01 web sshd[1234]: Failed password for root port 4321 ssh2")
	second := collapseKey("Jun  1 10:21:07 web sshd[9876]: Failed password for root port 5555 ssh2")
	if first != second {
		t.Fatalf("brute-force lines should share a key:\n%s\n%s", first, second)
	}
	if strings.Contains(first, "1234") || strings.Contains(first, "4321") {
		t.Fatalf("the key should erase pid and port: %q", first)
	}
}

// The accounting stores' closing line names the window the file covers, not a
// login: both dialects print it under last's and lastb's rows, with the space
// some util-linux versions leave in front, and the panel drops it. The empty
// store's own notice is a reading, so it stays.
func TestLoginTrailerDropsTheClosingLineOnly(t *testing.T) {
	record := func(line string) *model.Record {
		rec := model.TextRecord(line)
		return &rec
	}
	for _, line := range []string{
		"wtmp begins Wed Jul 29 13:41:26 2026",
		"btmp begins Thu Oct  8 07:17:01 2026",
		"wtmpdb begins Thu Oct  8 16:08:04 2026",
		" wtmp begins Mon Jan  1 00:00:00 1970",
	} {
		if !loginTrailer.Match(record(line)) {
			t.Errorf("%q is the accounting store's closing line", line)
		}
	}
	for _, line := range []string{
		"lab      pts/44       10.211.55.2      Thu Oct  8 07:35 - 07:35  (00:00)",
		"reboot   system boot  5.15.0-198-generic Thu Oct  8 07:14",
		"/var/log/wtmp has no entries",
		"wtmp",
	} {
		if loginTrailer.Match(record(line)) {
			t.Errorf("%q is evidence, not the store's closing line", line)
		}
	}
}
