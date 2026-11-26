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
	if module, spec, ok := GraphTarget("boot"); !ok {
		t.Errorf("the boot graph word is missing from the registry")
	} else if spec.Build == nil || module.Bit != DomainPersistence {
		t.Errorf("the boot graph spec = %+v for module %+v", spec, module)
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

func TestWebHeadQuotesTheScript(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shell.php")
	body := "<?php\n\n// dropper\nsystem($_GET['c']);\nheader('x');\necho 1;\n?>\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	quotes := webHead(path)
	if len(quotes) != 5 {
		t.Fatalf("quotes = %+v, want five non-empty lines", quotes)
	}
	if quotes[0].Line != 1 || quotes[1].Line != 3 || quotes[2].Line != 4 || quotes[4].Line != 6 {
		t.Errorf("line numbers = %d %d %d %d, want 1 3 4 6", quotes[0].Line, quotes[1].Line, quotes[2].Line, quotes[4].Line)
	}
	if quotes[1].Text != "// dropper" {
		t.Errorf("second line = %q", quotes[1].Text)
	}
	long := filepath.Join(t.TempDir(), "long.php")
	if err := os.WriteFile(long, []byte(strings.Repeat("a", 300)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	capped := webHead(long)
	if len(capped) != 1 || len([]rune(capped[0].Text)) != 200 {
		t.Errorf("a long line is %d runes, want 200", len([]rune(capped[0].Text)))
	}
}

func TestWebScriptFindingCitesItsHead(t *testing.T) {
	path := "/var/www/html/uploads/shell.php"
	facts := pathFacts(path, 1200, 0o644, 33)
	head := []Quote{{Path: path, Line: 1, Text: "<?php system($_GET['c']); ?>"}}
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{path: facts},
		Web: WebState{
			Roots: []string{"/var/www"},
			Files: []WebFile{{Path: path, Root: "/var/www", Facts: facts, Head: head}},
		},
	}
	report := Judge(snapshot, Filter{})
	for _, finding := range report.Findings {
		if finding.Class != "web-script" {
			continue
		}
		if len(finding.Quotes) != 1 || finding.Quotes[0] != head[0] {
			t.Errorf("quotes = %+v, want %+v", finding.Quotes, head)
		}
		return
	}
	t.Fatalf("findings = %+v, want web-script", report.Findings)
}
