package windows

import (
	"runtime"
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/testkit"
)

// psScripts collects every probe script in the catalog that is fed into powershell
// -Command. PS 5.1 treats a newline inside a statement as a statement separator: a
// foreach header split across lines is a parse error (hit on a real Server 2025
// box), and a trailing pipe is likewise invalid.
func psScripts() map[string]string {
	scripts := map[string]string{}
	for _, check := range All {
		for _, step := range check.Steps {
			for _, probe := range step {
				argv, ok := probe.Inv.(model.Command)
				if !ok || argv.Argv[0] != "powershell" {
					continue
				}
				scripts[check.ID+"·"+probe.Label] = argv.Argv[len(argv.Argv)-1]
			}
		}
	}
	return scripts
}

func TestPowerShellScriptsAreOneStatementPerLine(t *testing.T) {
	for name, script := range psScripts() {
		for _, line := range strings.Split(script, "\n") {
			trimmed := strings.TrimRight(line, " \t")
			if strings.HasSuffix(trimmed, "|") {
				t.Errorf("%s: trailing pipe is a parse error in PS 5.1: %q", name, line)
			}
			if strings.Contains(line, "foreach (") && !strings.Contains(line, ") {") {
				t.Errorf("%s: foreach header split across lines is a parse error: %q", name, line)
			}
		}
	}
}

// A generated script never prints a section header: a section is a probe's own
// title (model.BodySection), so no line the target read can become one.
func TestScriptsCarryNoSectionHeader(t *testing.T) {
	stringProbes := []model.Probe{
		stringsProbe("UTF8", 8, activityGlob),
		stringsProbe("Unicode", 5, `C:\Users\*\Recent\AutomaticDestinations\*`),
		jumplistProbe,
	}
	for _, probe := range stringProbes {
		names := []string{"list"}
		scripts := []string{callScript(t, probe.Files.List)}
		for _, path := range []string{`C:\Users\x\Recent\a.lnk`, `C:\Windows\AppCompat\Custom\b.sdb`} {
			names = append(names, "read"+path)
			scripts = append(scripts, callScript(t, probe.Files.Read(path)))
		}
		for index, script := range scripts {
			if strings.Contains(script, "'== '") {
				t.Errorf("%s %s still prints a section header: %q", names[index], names[0], script)
			}
		}
	}
}

// callScript is the script text of one PowerShell invocation.
func callScript(t *testing.T, inv model.Invocation) string {
	t.Helper()
	command, ok := inv.(model.Command)
	if !ok || len(command.Argv) == 0 {
		t.Fatalf("not a command invocation: %#v", inv)
	}
	return command.Argv[len(command.Argv)-1]
}

// TestUTF16Strings dual-phase extraction: odd-aligned names must also be recovered, and fake CJK
// strings read from the wrong phase ("all-zero low bytes") must be dropped.
func TestUTF16Strings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("byte-level case, platform-independent, guards against implementation regressions")
	}
	u16 := func(s string) []byte {
		out := make([]byte, 0, 2*len(s))
		for _, r := range s {
			out = append(out, byte(r), byte(r>>8))
		}
		return out
	}
	t.Run("even-aligned ASCII", func(t *testing.T) {
		got := UTF16Strings(u16("Auto\x00\x00"), 3)
		if len(got) != 1 || got[0] != "Auto" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("odd-aligned ASCII no longer garbled", func(t *testing.T) {
		data := append([]byte{0x00}, u16("Auto")...) // shifted by one byte overall
		got := UTF16Strings(data, 3)
		if len(got) != 1 || got[0] != "Auto" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("misaligned fake CJK dropped", func(t *testing.T) {
		// when the correct phase reads ASCII, the wrong phase reads the same run as CJK with all-zero low bytes
		data := u16("Auto")
		got := UTF16Strings(data[1:], 3) // read whole run from the misaligned phase
		for _, s := range got {
			for _, r := range s {
				if r < 0x10000 && r&0xFF == 0 {
					t.Fatalf("misaligned string with all-zero low bytes leaked into result: %q", got)
				}
			}
		}
	})
	t.Run("CJK and ASCII mixed run kept", func(t *testing.T) {
		got := UTF16Strings(u16("内存.7z"), 2)
		if len(got) != 1 || got[0] != "内存.7z" {
			t.Fatalf("got %q", got)
		}
	})
}

// The Administrators group carries the machine's own account on a
// domain-joined host (DOMAIN\PC$): it is the host itself, so the probe drops it
// before the rule can call it a hidden account. The filter belongs in the
// script because only the script knows this machine's name.
func TestAdminGroupDropsTheMachineAccount(t *testing.T) {
	probe := testkit.CheckByID(t, All, "admin-group").Steps[0][0]
	argv, ok := probe.Inv.(model.Command)
	if !ok {
		t.Fatalf("admin-group should be a PowerShell probe: %+v", probe.Inv)
	}
	script := argv.Argv[len(argv.Argv)-1]
	for _, want := range []string{"$env:COMPUTERNAME + '$'", "Where-Object"} {
		if !strings.Contains(script, want) {
			t.Errorf("the script should drop %s: %q", want, script)
		}
	}
}
