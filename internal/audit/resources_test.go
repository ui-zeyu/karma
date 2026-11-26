package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"karma/internal/startup"
	"karma/internal/trust"
)

func TestParseSSHDConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte(
		"AuthorizedKeysFile /tmp/keys\nPermitRootLogin yes\nPasswordAuthentication no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := parseSSHD([]string{path}, 0)
	if len(config.AuthorizedKeysFile) != 1 || config.AuthorizedKeysFile[0] != "/tmp/keys" {
		t.Errorf("authorized keys file = %v", config.AuthorizedKeysFile)
	}
	if config.PermitRootLogin != "yes" || config.PasswordAuthentication != "no" {
		t.Errorf("sshd = %+v", config)
	}
}

func TestClockJudge(t *testing.T) {
	snapshot := &Snapshot{
		Clock: ClockState{
			Now: time.Unix(10_000, 0), Boot: time.Unix(9_000, 0),
			Uptime: 10 * time.Minute, Skew: 0,
		},
		Boundary: Boundary{Time: time.Unix(20_000, 0), Kind: "host", Source: "package"},
		Objects: map[string]trust.Facts{
			"/tmp/future": pathFacts("/tmp/future", 30_000, 0o644, 0),
		},
	}
	var found bool
	Judge(snapshot, Filter{}) // no panic
	report := Judge(snapshot, Filter{})
	for _, finding := range report.Findings {
		if finding.Class == "clock-boundary" {
			found = true
		}
		if finding.Class == "future-timestamp" && finding.Path != "/tmp/future" {
			t.Errorf("future timestamp = %+v", finding)
		}
	}
	if !found {
		t.Errorf("findings = %+v, want clock-boundary", report.Findings)
	}
}

func TestWebScriptAndSeverity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shell.php")
	if err := os.WriteFile(path, []byte("<?php echo 1; ?>"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal(err)
	}
	if !webScript(path, entries[0]) {
		t.Errorf("php file was not a web script")
	}
	if packageFileSeverity("/usr/bin/true") != High || packageFileSeverity("/usr/share/doc/x") != Low {
		t.Errorf("package severity classification is wrong")
	}
}

func TestBootGraphAndGraphFindings(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Activations: []startup.Edge{{
			Surface: startup.SurfaceSystemd, Phase: startup.BootEnabled,
			Subject:   startup.Subject{Class: startup.AccountRoot},
			Trigger:   "/etc/systemd/system/agent.service",
			Mechanism: "ExecStart", Target: "/opt/agent/bin",
			TriggerFacts: pathFacts("/etc/systemd/system/agent.service", 1_000, 0o644, 0),
			TargetFacts:  pathFacts("/opt/agent/bin", 1_000, 0o755, 0),
		}},
	}
	graph := bootGraph(snapshot)
	if len(graph.Nodes) != 4 || len(graph.Edges) != 3 {
		t.Errorf("graph = %d nodes %d edges", len(graph.Nodes), len(graph.Edges))
	}
	findings := domainFindings(DomainPersistence, []Finding{
		{Class: "activation-introduction", Domain: DomainPersistence}, {Class: "identity-uid0", Domain: DomainIdentity},
	})
	if len(findings) != 1 || findings[0].Class != "activation-introduction" {
		t.Errorf("graph findings = %+v", findings)
	}
	if _, err := BuildDomainGraph("boot", snapshot, nil, nil); err != nil {
		t.Errorf("boot graph command failed: %v", err)
	}
}

func TestDormantModuleName(t *testing.T) {
	if moduleName("zz-probe.ko.zst") != "zz_probe" {
		t.Errorf("dormant module name = %q", moduleName("zz-probe.ko.zst"))
	}
	if !strings.HasSuffix(moduleName("x.ko"), "x") {
		t.Errorf("module name lost")
	}
}
