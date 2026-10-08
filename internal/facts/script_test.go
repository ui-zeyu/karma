package facts

import (
	"os/exec"
	"strings"
	"testing"
)

// Fact collection ships one dash script: syntax is checked with sh -n, pinned as a test instead of a manual step.
func TestFactShellScriptsParse(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh, skipping script syntax check")
	}
	for _, script := range []string{hostnameScript} {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("script syntax failed: %v\n%s", err, out)
		}
	}
}

// The Windows facts are one call each, and none of them prints a section header: a
// fact is one value, and the call that asked for it already names it.
func TestWindowsFactScriptsCarryNoSectionHeader(t *testing.T) {
	for name, script := range windowsFactScripts {
		if strings.Contains(script, "==") {
			t.Errorf("%s script still prints a section header: %q", name, script)
		}
		if strings.Contains(script, "\n") {
			t.Errorf("%s script spans lines, which PS 5.1 reads as separate statements: %q", name, script)
		}
	}
}
