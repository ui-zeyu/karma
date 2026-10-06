// The services check reads both probe formats through one keep filter, and the
// filter decides what the panel shows: this pins the rows it is for.

package linux

import (
	"slices"
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/reader"
	"karma/internal/testkit"
)

// keptLines runs the services check's filters over a body and returns the lines
// that reached the panel.
func keptLines(t *testing.T, body string) []string {
	t.Helper()
	check := testkit.CheckByID(t, All, "services")
	document := reader.Analyze(body, check.Rules, check.Filters, 0, model.FloorAll)
	var kept []string
	for _, section := range document.Sections {
		for _, line := range section.Lines {
			kept = append(kept, line.Text)
		}
	}
	return kept
}

// The ACTIVE column is what the filter reads: a state word in DESCRIPTION
// ("GRUB failed boot detection") does not make an inactive unit worth showing,
// and a failed unit — which systemctl marks with a leading ●, pushing ACTIVE one
// field right — is what the check exists to show.
func TestServicesKeepReadsTheActiveColumn(t *testing.T) {
	cases := []struct {
		line string
		keep bool
	}{
		{"  ssh.service      loaded active   running   OpenBSD Secure Shell server", true},
		{"  cron.service     loaded active   waiting   Regular background program processing", true},
		{"● karma-test.service loaded failed failed  /bin/false", true},
		{"  grub-initrd-fallback.service loaded inactive dead GRUB failed boot detection", false},
		{"  update-notifier-download.service loaded inactive dead Download data for packages that failed at install", false},
		{"  dev-cdrom.device loaded inactive dead CD-ROM Drive", false},
		{" [ + ]  apache2", true},
		{" [ - ]  cron", true},
	}
	for _, c := range cases {
		kept := slices.Contains(keptLines(t, c.line+"\n"), c.line)
		if kept != c.keep {
			t.Errorf("%q kept = %v, want %v", c.line, kept, c.keep)
		}
	}
}

// The header reaches the panel with the rows: the table lexer anchors its
// columns on it, and without it the whole table degrades to word cycling.
func TestServicesKeepCarriesTheHeader(t *testing.T) {
	body := "  UNIT                     LOAD   ACTIVE   SUB     DESCRIPTION\n" +
		"  ssh.service              loaded active   running OpenBSD Secure Shell server\n"
	kept := keptLines(t, body)
	if len(kept) != 2 || !strings.HasPrefix(kept[0], "  UNIT") {
		t.Fatalf("the header should reach the panel with its rows, got %q", kept)
	}
}
