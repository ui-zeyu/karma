package windows

import (
	"runtime"
	"strings"
	"testing"
)

// psScripts are all scripts that must be fed into powershell -Command. PS 5.1 treats a newline inside
// a statement as a statement separator: a foreach header split across lines is a parse error (hit on a
// real Server 2025 box), and a trailing pipe is likewise invalid.
func psScripts() map[string]string {
	scripts := map[string]string{
		"psreadline":    psHistoryScript,
		"jumplists":     jumplistScript,
		"office-mru":    officeScript,
		"lnk-recent":    lnkScript,
		"usb-devices":   usbScript,
		"activity":      stringsScript(activityGlob, 8),
		"sticky":        stringsScript(stickyGlob, 6),
		"shellbags-reg": shellbagScript,
		"wordwheel":     wordwheelScript,
		"typedpaths":    typedpathsScript,
		"recent-docs":   recentDocsScript,
		"comdlg32":      comdlg32Script,
		"adobe":         adobeScript,
		"archive":       archiveScript,
		"putty":         puttyScript,
		"rdp":           rdpScript,
		"userassist":    userassistScript,
		"track":         trackScript,
		"runmru":        runmruScript,
		"software":      softwareScript,
		"hotfixes":      hotfixScript,
		"env-vars":      RegScript(RegQuery(`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, false), RegQuery(`HKCU\Environment`, false)),
		"shares":        sharesScript,
		"rdp-config":    RegScript(RegValueQuery(`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections"), RegValueQuery(`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, "UserAuthentication"), RegValueQuery(`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "PortNumber")),
		"local-users":   localUsersScript,
		"admin-group":   adminGroupScript,
		"processes":     processesScript,
		"win-hosts":     winHostsScript,
		"run-keys":      runKeysScript,
		"nt-services":   servicesScript,
		"tasks":         tasksScript,
		"wmi-sub":       wmiSubscriptionScript,
		"sec-log":       secLogScript,
		"scriptblock":   scriptBlockScript,
		"remote-ctrl":   remoteCtrlScript,
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

// String-extraction section titles are printed only with body text: a readable file with zero hits leaves no ghost section.
func TestStringsScriptsTitleOnlyWithBody(t *testing.T) {
	for _, script := range []string{stringsScript(activityGlob, 8), stringsScript(stickyGlob, 6)} {
		if !strings.Contains(script, `if ($s) { "== " + $f.FullName; $s }`) {
			t.Errorf("section title should be emitted conditionally with $s: %q", script)
		}
		if strings.Count(script, `"== " + $f.FullName`) != 2 {
			t.Errorf("title should appear only for a hit and a read failure: %q", script)
		}
	}
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
