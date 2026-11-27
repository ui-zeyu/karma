package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"karma/internal/trust"
)

func TestParseIdentitySkipsNISCompatRows(t *testing.T) {
	accounts := parsePasswd("root:x:0:0:root:/root:/bin/bash\n+::0:0:::\n-::::::\n", "/etc/passwd")
	if len(accounts) != 1 || accounts[0].Name != "root" {
		t.Errorf("NIS rows became accounts: %+v", accounts)
	}
	if rows := parseShadow("+::::::::\nroot::19000:0:99999:7:::\n", "/etc/shadow"); len(rows) != 1 || rows["root"].Name != "root" {
		t.Errorf("NIS rows became shadow records: %+v", rows)
	}
	if groups := parseGroup("+:::\nroot:x:0:\n", "/etc/group"); len(groups) != 1 || groups[0].Name != "root" {
		t.Errorf("NIS rows became groups: %+v", groups)
	}
}

func TestParseIdentityRecords(t *testing.T) {
	accounts := parsePasswd(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"deploy:x:0:0:deploy:/home/deploy:/bin/bash\n"+
			"backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"+
			"bad-record\n", "/etc/passwd")
	if len(accounts) != 3 {
		t.Fatalf("accounts = %+v", accounts)
	}
	if accounts[1].Name != "deploy" || accounts[1].UID != 0 || accounts[1].System {
		t.Errorf("uid0 account = %+v", accounts[1])
	}
	if accounts[1].Line != 2 || accounts[1].Raw != "deploy:x:0:0:deploy:/home/deploy:/bin/bash" {
		t.Errorf("passwd row = %d %q", accounts[1].Line, accounts[1].Raw)
	}
	shadow := parseShadow("root::19000:0:99999:7:::\nbackup:!:19000:0:99999:7:::\n", "/etc/shadow")
	applyShadow(accounts, shadow)
	if !accounts[0].ShadowKnown || accounts[0].Shadow != "" || accounts[0].Locked {
		t.Errorf("root shadow = %+v", accounts[0])
	}
	if accounts[0].ShadowFile != "/etc/shadow" || accounts[0].ShadowLine != 1 ||
		accounts[0].ShadowRaw != "root::19000:0:99999:7:::" {
		t.Errorf("shadow row = %q:%d %q", accounts[0].ShadowFile, accounts[0].ShadowLine, accounts[0].ShadowRaw)
	}
	if !accounts[2].Locked {
		t.Errorf("locked shadow = %+v", accounts[2])
	}
	groups := parseGroup("root:x:0:\ndocker:x:999:deploy,alice\n", "/etc/group")
	if len(groups) != 2 || groups[1].Members[0] != "deploy" {
		t.Errorf("groups = %+v", groups)
	}
	if groups[1].Line != 2 || groups[1].Raw != "docker:x:999:deploy,alice" {
		t.Errorf("group row = %d %q", groups[1].Line, groups[1].Raw)
	}
}

func TestParseSudoers(t *testing.T) {
	grants := parseSudoers("Defaults env_reset\n"+
		"root ALL=(ALL:ALL) ALL\n"+
		"deploy ALL=(ALL) NOPASSWD: /bin/sh, PASSWD: /bin/ls\n", "/etc/sudoers", newSudoersTables())
	if len(grants) != 3 {
		t.Fatalf("grants = %+v", grants)
	}
	if grants[1].User != "deploy" || !grants[1].NoPasswd || grants[1].Command != "/bin/sh" {
		t.Errorf("deploy grant = %+v", grants[1])
	}
	if grants[2].NoPasswd || grants[2].Command != "/bin/ls" {
		t.Errorf("passwd grant = %+v", grants[2])
	}
	if grants[1].Raw != "deploy ALL=(ALL) NOPASSWD: /bin/sh, PASSWD: /bin/ls" || grants[1].Line != 3 {
		t.Errorf("deploy row = %d %q", grants[1].Line, grants[1].Raw)
	}
}

func TestParseSudoersJoinsContinuationLines(t *testing.T) {
	grants := parseSudoers("deploy ALL=(ALL) NOPASSWD: /bin/sh, \\\n/bin/ls\n", "/etc/sudoers", newSudoersTables())
	if len(grants) != 2 {
		t.Fatalf("grants = %+v", grants)
	}
	if grants[0].Raw != "deploy ALL=(ALL) NOPASSWD: /bin/sh,  /bin/ls" || grants[0].Line != 2 {
		t.Errorf("continuation row = %d %q", grants[0].Line, grants[0].Raw)
	}
}

func TestJudgedIdentityBackdoorCorrelation(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{},
		Identity: IdentityState{
			Accounts: []Account{{
				Name: "deploy", UID: 0, GID: 999, Shell: "/bin/bash",
				Password: "x", Shadow: "", ShadowKnown: true, Source: "/etc/passwd",
			}},
			Groups: []Group{{Name: "docker", GID: 999, Members: []string{"deploy"}}},
			Sudo: []SudoGrant{{
				User: "deploy", Host: "ALL", RunAs: "ALL", Command: "/bin/sh",
				NoPasswd: true, File: "/etc/sudoers.d/deploy", Line: 1,
			}},
			KeyCommands: []AuthorizedKeyCommand{{
				File: "/root/.ssh/authorized_keys", Account: "deploy", Command: "/bin/sh",
			}},
			SSHD: SSHDConfig{Files: []string{"/etc/ssh/sshd_config"}},
		},
	}
	report := Judge(snapshot, Filter{})
	var backdoor *Finding
	for index := range report.Findings {
		if report.Findings[index].Class == "identity-backdoor" {
			backdoor = &report.Findings[index]
		}
	}
	if backdoor == nil {
		t.Fatalf("findings = %+v, want identity-backdoor", report.Findings)
	}
	if backdoor.Severity != Critical || len(backdoor.Trace) < 4 {
		t.Errorf("backdoor = %+v", backdoor)
	}
	for _, finding := range report.Findings {
		if strings.HasPrefix(string(finding.Class), "identity-") && finding.Class != "identity-backdoor" &&
			finding.Class != "identity-sshd-keyfile" {
			t.Errorf("correlated account also emitted %s", finding.Class)
		}
	}
}

func TestIdentitySingleFactorAndStockAccount(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{},
		Identity: IdentityState{
			Accounts: []Account{
				{Name: "deploy", UID: 1000, GID: 1000, Shell: "/bin/bash", Password: "x", Shadow: "", ShadowKnown: true},
				{Name: "syslog", UID: 104, GID: 4, Shell: "/usr/sbin/nologin", System: true, Password: "x", ShadowKnown: false},
			},
			Groups: []Group{{Name: "adm", GID: 4, Members: []string{"syslog"}}},
		},
	}
	report := Judge(snapshot, Filter{})
	if len(report.Findings) != 1 || report.Findings[0].Class != "identity-empty-password" {
		t.Fatalf("findings = %+v", report.Findings)
	}
	if report.Findings[0].Severity != High {
		t.Errorf("empty user password = %s", report.Findings[0].Severity)
	}
}

func TestParseSSHDCapturesTheKeyDirective(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sshd_config")
	body := "# comment\nAuthorizedKeysFile /etc/ssh/authorized_keys.d/%u\nPermitRootLogin no\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	config := parseSSHD([]string{path}, 0)
	if config.KeyFile != path || config.KeyLine != 2 ||
		config.KeyRaw != "AuthorizedKeysFile /etc/ssh/authorized_keys.d/%u" {
		t.Errorf("key directive = %q:%d %q", config.KeyFile, config.KeyLine, config.KeyRaw)
	}
}

func TestParseSSHDAndKeyCommand(t *testing.T) {
	config := parseSSHD([]string{t.TempDir() + "/missing"}, 0)
	if len(config.Files) != 0 {
		t.Errorf("missing sshd config read: %+v", config)
	}
	if !shellCommand("/bin/sh -c id") || shellCommand("/usr/local/bin/backup") {
		t.Errorf("shellCommand classification is wrong")
	}
}

func TestIdentityGraphHasRelations(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Identity: IdentityState{
			Accounts: []Account{{Name: "deploy", UID: 0, Shell: "/bin/bash"}},
			Groups:   []Group{{Name: "docker", Members: []string{"deploy"}}},
			Sudo:     []SudoGrant{{User: "deploy", Command: "/bin/sh", NoPasswd: true, File: "/etc/sudoers"}},
		},
	}
	graph := identityGraph(snapshot)
	if len(graph.Nodes) < 4 || len(graph.Edges) < 3 {
		t.Errorf("graph = %d nodes %d edges", len(graph.Nodes), len(graph.Edges))
	}
}

func TestIdentityFindingsCiteTheirRows(t *testing.T) {
	passwd := Quote{Path: "/etc/passwd", Line: 7, Text: "svc:x:1000:1000::/home/svc:/usr/sbin/nologin"}
	shadow := Quote{Path: "/etc/shadow", Line: 7, Text: "svc:!:19000:0:99999:7:::"}
	account := Account{
		Name: "svc", UID: 1000, GID: 1000, Shell: "/usr/sbin/nologin", Password: "x",
		Shadow: "!", ShadowKnown: true,
		Source: "/etc/passwd", Line: 7, Raw: passwd.Text,
		ShadowFile: "/etc/shadow", ShadowLine: 7, ShadowRaw: shadow.Text,
	}
	group := Group{Name: "docker", GID: 999, Members: []string{"svc"}, Source: "/etc/group", Line: 3, Raw: "docker:x:999:svc"}
	grant := SudoGrant{
		User: "svc", Host: "ALL", RunAs: "ALL", Command: "/bin/sh", NoPasswd: true,
		File: "/etc/sudoers.d/svc", Line: 2, Raw: "svc ALL=(ALL) NOPASSWD: /bin/sh",
	}
	key := Quote{Path: "/etc/ssh/sshd_config", Line: 4, Text: "AuthorizedKeysFile /etc/ssh/keys/%u"}

	root := account
	root.UID = 0
	system := account
	system.UID, system.System, system.Shell = 104, true, "/bin/bash"
	empty := account
	empty.Shadow, empty.Locked = "", false

	cases := []struct {
		name  string
		state IdentityState
		class string
		quote Quote
	}{
		{"uid 0", IdentityState{Accounts: []Account{root}}, "identity-uid0", passwd},
		{"correlated backdoor", IdentityState{Accounts: []Account{root}, Groups: []Group{group}},
			"identity-backdoor", passwd},
		{"system shell", IdentityState{Accounts: []Account{system}}, "identity-system-shell", passwd},
		{"empty password", IdentityState{Accounts: []Account{empty}}, "identity-empty-password", shadow},
		{"privileged group", IdentityState{Accounts: []Account{account}, Groups: []Group{group}},
			"identity-privileged-group", Quote{Path: group.Source, Line: group.Line, Text: group.Raw}},
		{"sudo grant", IdentityState{Sudo: []SudoGrant{grant}}, "identity-sudo-nopasswd",
			Quote{Path: grant.File, Line: grant.Line, Text: grant.Raw}},
		{"sshd key file", IdentityState{SSHD: SSHDConfig{
			Files: []string{"/etc/ssh/sshd_config"}, AuthorizedKeysFile: []string{"/etc/ssh/keys/%u"},
			KeyFile: key.Path, KeyLine: key.Line, KeyRaw: key.Text,
		}}, "identity-sshd-keyfile", key},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			snapshot := &Snapshot{Boundary: boundary(), Objects: map[string]trust.Facts{}, Identity: test.state}
			report := Judge(snapshot, Filter{})
			for _, finding := range report.Findings {
				if string(finding.Class) != test.class {
					continue
				}
				if len(finding.Quotes) != 1 || finding.Quotes[0] != test.quote {
					t.Errorf("quotes = %+v, want %+v", finding.Quotes, test.quote)
				}
				return
			}
			t.Errorf("findings = %+v, want %s", report.Findings, test.class)
		})
	}
}

func TestSudoersResolvesGrantsFromNestedIncludes(t *testing.T) {
	dir := t.TempDir()
	top := filepath.Join(dir, "sudoers")
	nested := filepath.Join(dir, "included")
	body := "User_Alias ADMINS = deploy\n@include " + nested + "\n"
	if err := os.WriteFile(top, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nested, []byte("ADMINS ALL=(ALL) NOPASSWD: /bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	grants := parseSudoersFiles([]string{top}, 0)
	if len(grants) != 1 {
		t.Fatalf("grants = %+v, want the nested file's grant", grants)
	}
	grant := grants[0]
	if grant.User != "deploy" || grant.Command != "/bin/sh" || !grant.NoPasswd {
		t.Errorf("grant = %+v, want deploy's passwordless /bin/sh resolved through the nested include", grant)
	}
}
