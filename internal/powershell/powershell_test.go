package powershell

import (
	"slices"
	"testing"
)

func TestPowerShellWrapsTheScriptIntoOneCommand(t *testing.T) {
	cmd := PowerShell("Get-Date")
	want := []string{
		"powershell", "-NoProfile", "-NonInteractive", "-Command",
		"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;Get-Date",
	}
	if !slices.Equal(cmd.Argv, want) {
		t.Fatalf("argv = %q, want %q", cmd.Argv, want)
	}
}
