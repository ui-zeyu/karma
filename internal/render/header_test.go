package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"karma/internal/model"
)

// The report header is the report's first rail panel: the karma band over the
// host facts, the system line and the severity legend below, everything inside
// the line width and wearing the same rail as a check panel.
func TestRenderHeader(t *testing.T) {
	facts := model.HostFacts{
		Hostname: "web-01",
		User:     `CORP\alice`,
		OsPretty: "Ubuntu 22.04",
		Kernel:   "5.15.0-91-generic",
		UID:      0,
	}
	var out bytes.Buffer
	RenderHeader(&out, "ssh", facts, 100, model.FloorAll)
	text := out.String()
	body := plain(text)
	for _, want := range []string{"web-01", `CORP\alice`, "root", "Ubuntu 22.04", "5.15.0-91-generic", "ssh", "critical", "high", "medium", "low"} {
		if !strings.Contains(body, want) {
			t.Fatalf("header should carry %q:\n%s", want, body)
		}
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if !strings.HasPrefix(lines[0], "▌ KARMA") {
		t.Fatalf("the header opens with the karma band on the panel rail:\n%s", body)
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "▌  ") {
			t.Fatalf("header rows sit in the panel body, indented behind the rail:\n%s", body)
		}
	}
	for i, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if width := lipgloss.Width(line); width > 99 {
			t.Fatalf("header line %d is %d columns wide, over the line width: %q", i, width, plain(line))
		}
	}
}
