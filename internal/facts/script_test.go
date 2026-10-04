package facts

import (
	"os/exec"
	"strings"
	"testing"
)

// Fact collection ships two dash scripts: syntax is now checked with sh -n, pinned as a test instead of a manual step.
func TestFactShellScriptsParse(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh, skipping script syntax check")
	}
	for _, script := range []string{hostnameScript, binProbe([]string{"find", "docker"})} {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("script syntax failed: %v\n%s", err, out)
		}
	}
}

func TestLabeledLines(t *testing.T) {
	stdout := "== host\r\nWIN-XP\r\n\r\n== user\r\nBOX\\john\r\n== os\r\n\r\n \r\n== os\r\nWindows XP\r\n"
	got := labeledLines(stdout)
	if got["host"] != "WIN-XP" || got["user"] != `BOX\john` {
		t.Fatalf("wrong section collapse: %+v", got)
	}
	// after empty sections are skipped, the next line of the same-name section is the first non-empty line
	if got["os"] != "Windows XP" {
		t.Fatalf("os section should take the first non-empty line: %q", got["os"])
	}
	// preamble (untitled) lines do not enter the map
	if _, ok := labeledLines("preamble\n== host\nx")[""]; ok {
		t.Fatal("preamble should not enter the map")
	}
}
