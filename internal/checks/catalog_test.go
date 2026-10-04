package checks_test

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"karma/internal/checks"
	"karma/internal/checks/linux"
	"karma/internal/model"
)

func TestCatalogShape(t *testing.T) {
	linux := checks.ChecksFor(model.Linux)
	if len(linux) != 70 {
		t.Fatalf("the Linux catalog should hold 70 checks, got %d", len(linux))
	}
	windows := checks.ChecksFor(model.Windows)
	if len(windows) != 37 {
		t.Fatalf("the Windows catalog should hold 37 checks, got %d", len(windows))
	}
	aspects := map[model.Aspect]bool{}
	for _, check := range windows {
		aspects[check.Aspect] = true
		for _, rule := range check.Rules {
			if rule.ID == "reverse-shell-dev-tcp" {
				t.Fatalf("%s must not carry a Linux global rule", check.ID)
			}
		}
		if !slices.ContainsFunc(check.Filters, func(f model.LineFilter) bool { return f.ID == "blank" }) {
			t.Fatalf("%s is missing the blank-line filter", check.ID)
		}
	}
	for _, aspect := range []model.Aspect{
		model.AspectSystem, model.AspectIdentity, model.AspectProcess,
		model.AspectNetwork, model.AspectPersistence,
		model.AspectExecution, model.AspectNavigation, model.AspectDocuments,
		model.AspectRemote, model.AspectLog, model.AspectTimeline,
		model.AspectDevices,
	} {
		if !aspects[aspect] {
			t.Fatalf("the Windows catalog is missing aspect %s", aspect)
		}
	}
	if len(aspects) != 12 {
		t.Fatalf("number of Windows aspects: %d", len(aspects))
	}
}

// Every dash script in the catalog passes sh -n: the syntax check for generated
// scripts is a test instead of a manual step. mtime is a dynamically built
// check, so a sample directory stands in for one.
func TestShellScriptsParse(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh, skipping the script syntax check")
	}
	var scripts []string
	for _, check := range checks.ChecksFor(model.Linux) {
		for _, probe := range check.Probes {
			if shell, ok := probe.Inv.(model.Shell); ok {
				scripts = append(scripts, check.ID+": "+shell.Script)
			}
		}
	}
	hunt := linux.HuntCheck([]string{"/tmp/demo", "/var/www"})
	for _, probe := range hunt.Probes {
		scripts = append(scripts, hunt.ID+": "+probe.Inv.(model.Shell).Script)
	}
	if len(scripts) == 0 {
		t.Fatal("the catalog should yield Shell scripts")
	}
	for _, item := range scripts {
		id, body, _ := strings.Cut(item, ": ")
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(body)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s script fails the syntax check: %v\n%s", id, err, out)
		}
	}
}
