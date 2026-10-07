package windows

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"karma/internal/model"
	"karma/internal/powershell"
	"karma/internal/regout"
	"karma/internal/testkit"
)

func utf16Hex(text string) string {
	encoded := utf16.Encode([]rune(text))
	raw := make([]byte, len(encoded)*2)
	for i, unit := range encoded {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ",")
}

func filetimeBytes(unix int64) []byte {
	ticks := uint64(unix)*10_000_000 + filetimeEpoch
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, ticks)
	return raw
}

func hexOf(raw []byte) string {
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ",")
}

func TestParseRegValuesJoinsWrappedBinary(t *testing.T) {
	body := strings.Join([]string{
		`HKEY_CURRENT_USER\Software\X`,
		`    MRUListEx    REG_BINARY    0C,00,00,00,01,00,00,00,\`,
		`        02,00,00,00,FF,FF,FF,FF`,
		`    Start_TrackEnabled    REG_DWORD    0x0`,
		`    Item 1    REG_SZ    hello world`,
	}, "\n")
	values := regout.ParseRegValues(body)
	names := make([]string, len(values))
	for i, value := range values {
		names[i] = value.Name
	}
	if strings.Join(names, ",") != "MRUListEx,Start_TrackEnabled,Item 1" {
		t.Fatalf("value names: %v", names)
	}
	if values[0].Data != "0C,00,00,00,01,00,00,00,02,00,00,00,FF,FF,FF,FF" {
		t.Fatalf("wrapped line not joined: %q", values[0].Data)
	}
	if values[1].Type != "REG_DWORD" || values[2].Name != "Item 1" {
		t.Fatalf("type or name wrong: %+v", values)
	}
}

func TestDecoders(t *testing.T) {
	data := append(utf16LE("C:\\Temp\\passwords\\users.txt"), 0, 0)
	if got := strings.Join(UTF16Strings(data, 3), "|"); got != `C:\Temp\passwords\users.txt` {
		t.Fatalf("utf16: %q", got)
	}
	got := ROT13(`{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\cbjrefuryy.rkr`)
	want := `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\powershell.exe`
	if got != want {
		t.Fatalf("rot13: %q", got)
	}
	if FiletimeStr(filetimeBytes(1672531200)) != "2023-01-01 00:00:00" {
		t.Fatalf("filetime: %q", FiletimeStr(filetimeBytes(1672531200)))
	}
	if FiletimeStr(nil) != "" {
		t.Fatal("empty filetime should be empty")
	}
	if !slices.Equal(regout.HexBytes("0C,00, FF"), []byte{0x0c, 0x00, 0xff}) {
		t.Fatalf("hex: %v", regout.HexBytes("0C,00, FF"))
	}
	if regout.HexBytes("not-hex") != nil {
		t.Fatal("invalid hex should be empty")
	}
}

func utf16LE(text string) []byte {
	encoded := utf16.Encode([]rune(text))
	raw := make([]byte, len(encoded)*2)
	for i, unit := range encoded {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return raw
}

func TestMRUListExWalksLinkedList(t *testing.T) {
	values := regout.ParseRegValues("    MRUListEx    REG_BINARY    02,00,00,00,00,00,00,00,01,00,00,00,FF,FF,FF,FF\n")
	if got := fmt.Sprint(MRUListExOrder(values)); got != "[2 1 0]" {
		t.Fatalf("list order: %s", got)
	}
	empty := regout.ParseRegValues("    MRUListEx    REG_BINARY    FF,FF,FF,FF\n")
	if MRUListExOrder(empty) != nil {
		t.Fatalf("leading terminator should be empty: %v", MRUListExOrder(empty))
	}
}

func TestMRUTermsOrderWordWheel(t *testing.T) {
	body := strings.Join([]string{
		wordwheelKey,
		"    MRUListEx    REG_BINARY    02,00,00,00,00,00,00,00,01,00,00,00,FF,FF,FF,FF",
		"    0    REG_BINARY    " + utf16Hex("password.txt") + ",00,00",
		"    1    REG_BINARY    " + utf16Hex("key.ppk") + ",00,00",
		"    2    REG_BINARY    " + utf16Hex("salary.xlsx") + ",00,00",
	}, "\n")
	if got := strings.Join(MRUTerms(body, 2), "|"); got != "salary.xlsx|key.ppk|password.txt" {
		t.Fatalf("search term order: %q", got)
	}
}

func TestUserassistNormalize(t *testing.T) {
	const countKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` +
		`\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`
	body := strings.Join([]string{
		countKey,
		"    Version    REG_DWORD    0x5",
		"    HRZR_PGYPHNPbhag:pgbe    REG_BINARY    00,00,00,00,00,00,00,00,00,00,00,00",
		"    {1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\\JvaqbjfCbjreFuryy\\i1.0\\cbjrefuryy.rkr" +
			"    REG_BINARY    00,00,00,00,0D,00,00,00,00,00,00,00",
	}, "\n")
	shaped := userassistNormalize(countKey, body)
	if shaped == nil || shaped.Text != `System32\WindowsPowerShell\v1.0\powershell.exe · ran 13 times` {
		t.Fatalf("userassist (Version and UEME session counters are per-subkey noise and should be filtered): %+v", shaped)
	}
}

func TestUserassistTrackLightsUp(t *testing.T) {
	check := testkit.CheckByID(t, All, "userassist-track")
	sectioned := strings.Join([]string{
		`== HKCU\...\Advanced\Start_TrackEnabled`,
		`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`,
		"    Start_TrackEnabled    REG_DWORD    0x0",
	}, "\n")
	if !slices.Contains(testkit.HitIDs(t, sectioned, check), "userassist-track-disabled") {
		t.Fatal("section body should match tracking disabled")
	}
	direct := "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\n" +
		"    Start_TrackProgs    REG_DWORD    0x0\n"
	if !slices.Contains(testkit.HitIDs(t, direct, check), "userassist-track-disabled") {
		t.Fatal("direct-run preamble section should match tracking disabled")
	}
}

func TestWordwheelSensitive(t *testing.T) {
	check := testkit.CheckByID(t, All, "wordwheel-query")
	text := strings.Join([]string{
		"== " + wordwheelKey,
		"    MRUListEx    REG_BINARY    00,00,00,00,FF,FF,FF,FF",
		"    0    REG_BINARY    " + utf16Hex("*password*.txt") + ",00,00",
	}, "\n")
	if !slices.Contains(testkit.HitIDs(t, text, check), "wordwheel-sensitive") {
		t.Fatal("sensitive search term should match")
	}
}

func TestRunMRUOrder(t *testing.T) {
	body := strings.Join([]string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`,
		"    MRUList    REG_SZ    cba",
		`    a    REG_SZ    cmd\1`,
		`    b    REG_SZ    powershell -enc AAA\1`,
		`    c    REG_SZ    \\10.0.0.5\share\1`,
	}, "\n")
	shaped := runmruNormalize("", body)
	want := "\\\\10.0.0.5\\share\npowershell -enc AAA\ncmd"
	if shaped == nil || shaped.Text != want {
		t.Fatalf("runmru: %q", shaped.Text)
	}
}

// Under structural parsing, entries with unlisted GUIDs only serve as path-chain
// placeholders. An all-GUID tree stays silent.
func TestShellbagDedupDropsGUID(t *testing.T) {
	key := `HKCU\Software\Classes\...\BagMRU`
	item := append([]byte{0x14, 0x00, 0x1f, 0x00},
		guidBytes("12345678-90AB-CDEF-1234-567890ABCDEF")...)
	shaped := shellbagNormalize("", key+"\n"+hexValues(
		[2]string{"0", string(item)},
		[2]string{"1", string(item)},
	))
	if shaped != nil {
		t.Fatalf("all-GUID entry should stay silent, got %q", shaped.Text)
	}
}

func TestOfficeMRUTimeAndPath(t *testing.T) {
	raw := append(filetimeBytes(1700611200), 0x04, 0x00, 0x00, 0x00)
	raw = append(raw, utf16LE(`C:\Users\john\Desktop\may_expenses.xlsx`)...)
	body := "HKEY_CURRENT_USER\\...\\File MRU\n    Item 1    REG_BINARY    " + hexOf(raw) + "\n"
	shaped := officeMruNormalize("16.0\\Excel\\File MRU", body)
	want := `2023-11-22 00:00:00  C:\Users\john\Desktop\may_expenses.xlsx`
	if shaped == nil || shaped.Text != want {
		t.Fatalf("office: %q", shaped.Text)
	}
}

func TestOpensaveDispatchesByBlock(t *testing.T) {
	body := strings.Join([]string{
		`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32`,
		"",
		`HKEY_CURRENT_USER\...\ComDlg32\CIDSizeMRU`,
		"    0    REG_BINARY    " + utf16Hex("NOTEPAD.EXE") + ",00,00",
		"",
		`HKEY_CURRENT_USER\...\ComDlg32\LastVisitedPidlMRU`,
		"    MRUListEx    REG_BINARY    00,00,00,00,FF,FF,FF,FF",
		"    0    REG_BINARY    " + utf16Hex("NOTEPAD.EXE") + ",00,00," + utf16Hex(`C:\Tools`) + ",00,00",
		"",
		`HKEY_CURRENT_USER\...\ComDlg32\OpenSavePidlMRU`,
		"",
		`HKEY_CURRENT_USER\...\ComDlg32\OpenSavePidlMRU\ps1`,
		"    MRUListEx    REG_BINARY    00,00,00,00,FF,FF,FF,FF",
		"    0    REG_BINARY    " + utf16Hex(`C:\Tools\Invoke-Mimikatz.ps1`) + ",00,00",
	}, "\n")
	shaped := opensaveNormalize("", body)
	want := "NOTEPAD.EXE\nNOTEPAD.EXE → C:\\Tools\nC:\\Tools\\Invoke-Mimikatz.ps1"
	if shaped == nil || shaped.Text != want {
		t.Fatalf("opensave: %q", shaped.Text)
	}
}

func TestRecentDocsWalksEveryExtensionBlock(t *testing.T) {
	body := strings.Join([]string{
		`HKEY_CURRENT_USER\...\RecentDocs`,
		"    MRUListEx    REG_BINARY    00,00,00,00,FF,FF,FF,FF",
		"    0    REG_BINARY    " + utf16Hex("users.txt") + ",00,00",
		"",
		`HKEY_CURRENT_USER\...\RecentDocs\.csv`,
		"    MRUListEx    REG_BINARY    01,00,00,00,00,00,00,00,FF,FF,FF,FF",
		"    0    REG_BINARY    " + utf16Hex("old.csv") + ",00,00",
		"    1    REG_BINARY    " + utf16Hex("salary_details.csv") + ",00,00",
	}, "\n")
	shaped := recentDocsNormalize("", body)
	want := "users.txt\nsalary_details.csv\nold.csv"
	if shaped == nil || shaped.Text != want {
		t.Fatalf("recent-docs: %q", shaped.Text)
	}
}

func TestArchiveNormalize(t *testing.T) {
	body := strings.Join([]string{
		`HKCU\SOFTWARE\WinZip Computing\WinZip\extract`,
		"    0    REG_SZ    C:\\Users\\john\\Downloads\\secret.zip",
		"    xd0    REG_BINARY    " + utf16Hex("picture1.png") + ",00,00",
	}, "\n")
	shaped := archiveNormalize("", body)
	want := "C:\\Users\\john\\Downloads\\secret.zip\npicture1.png"
	if shaped == nil || shaped.Text != want {
		t.Fatalf("archive: %q", shaped.Text)
	}
}

// RegCheck assembles the PowerShell script from the key list and appends one
// step of direct reg.exe fallbacks, one probe per key; pin the composed shape of
// both steps.
func TestRegCheckComposesScripts(t *testing.T) {
	runKeys := testkit.CheckByID(t, All, "run-keys")
	composed := runKeys.Steps[0][0].Inv.(model.Command).Argv[4]
	// every key queried once in the script, its section title printed only with output
	const runOnce = `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
	if got := strings.Count(composed, "reg query '"+runOnce+"' 2>$null"); got != 1 {
		t.Fatalf("key queried once: %d in %s", got, composed)
	}
	if !strings.Contains(composed, "if ($o) { '== ' + '"+runOnce+"'; $o }") {
		t.Fatalf("conditional section title missing: %s", composed)
	}
	// the extra startup-folder fragment comes after the key fragments
	if !strings.Contains(composed, `'== ' + 'Startup Folder'`) {
		t.Fatalf("startup folder fragment missing: %s", composed)
	}
	// one direct fallback per key, in key order, and all of them in one step: as
	// separate steps the walk would stop at the first key that exists and never
	// query the rest (the local Windows channel has no shell to loop in).
	if len(runKeys.Steps) != 2 {
		t.Fatalf("the PowerShell step and one step of reg fallbacks: %d steps", len(runKeys.Steps))
	}
	var fallbacks []string
	for _, probe := range runKeys.Steps[1] {
		fallbacks = append(fallbacks, probe.Inv.(model.Command).Argv[2])
	}
	want := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		runOnce,
	}
	if !slices.Equal(fallbacks, want) {
		t.Fatalf("fallback key order: %v", fallbacks)
	}

	// value queries: /v on both tiers
	track := testkit.CheckByID(t, All, "userassist-track")
	composed = track.Steps[0][0].Inv.(model.Command).Argv[4]
	if !strings.Contains(composed, `reg query '`+advancedKey+`' /v Start_TrackEnabled 2>$null`) {
		t.Fatalf("value query missing: %s", composed)
	}
	if argv := track.Steps[1][0].Inv.(model.Command).Argv; !slices.Equal(argv, []string{"reg", "query", advancedKey, "/v", "Start_TrackEnabled"}) {
		t.Fatalf("fallback /v argv: %v", argv)
	}
}

func TestRegistryChecksCarryRegFallback(t *testing.T) {
	dual := map[string]bool{}
	for _, check := range All {
		first := check.Steps[0][0]
		argv, ok := first.Inv.(model.Command)
		// Native command probes (system-guaranteed exes like netstat and schtasks) are not wrapped in PS
		if !ok || argv.Argv[0] != "powershell" {
			continue
		}
		if !slices.Equal(argv.Argv[:4], []string{"powershell", "-NoProfile", "-NonInteractive", "-Command"}) {
			t.Fatalf("%s first probe argv wrong: %v", check.ID, argv.Argv[:4])
		}
		if !strings.HasPrefix(argv.Argv[4], powershell.UTF8Prefix) {
			t.Fatalf("%s missing UTF-8 prefix", check.ID)
		}
		if len(check.Steps) > 1 {
			dual[check.ID] = true
			if len(check.Steps) != 2 {
				t.Fatalf("%s: one PowerShell step and one reg step, got %d steps", check.ID, len(check.Steps))
			}
			for _, probe := range check.Steps[1] {
				rest, ok := probe.Inv.(model.Command)
				if !ok || rest.Argv[0] != "reg" || rest.Argv[1] != "query" {
					t.Fatalf("%s fallback probe should be reg query: %+v", check.ID, probe.Inv)
				}
			}
		}
	}
	want := []string{
		"adobe-recent", "appcompat", "archive-history", "env-vars", "ifeo", "opensave-mru",
		"putty", "rdp-config", "rdp-history", "recent-docs", "remote-control", "run-keys",
		"runmru", "shellbags", "typedpaths", "userassist", "userassist-track", "winlogon",
		"wordwheel-query",
	}
	var got []string
	for id := range dual {
		got = append(got, id)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("dual-probe checks: %v", got)
	}
}
