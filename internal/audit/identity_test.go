package audit

import (
	"strings"
	"testing"

	"karma/internal/trust"
)

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
	shadow := parseShadow("root::19000:0:99999:7:::\nbackup:!:19000:0:99999:7:::\n", "/etc/shadow")
	applyShadow(accounts, shadow)
	if !accounts[0].ShadowKnown || accounts[0].Shadow != "" || accounts[0].Locked {
		t.Errorf("root shadow = %+v", accounts[0])
	}
	if !accounts[2].Locked {
		t.Errorf("locked shadow = %+v", accounts[2])
	}
	groups := parseGroup("root:x:0:\ndocker:x:999:deploy,alice\n", "/etc/group")
	if len(groups) != 2 || groups[1].Members[0] != "deploy" {
		t.Errorf("groups = %+v", groups)
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
		if strings.HasPrefix(finding.Class, "identity-") && finding.Class != "identity-backdoor" &&
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
