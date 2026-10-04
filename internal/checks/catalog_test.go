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
	if len(windows) != 42 {
		t.Fatalf("the Windows catalog should hold 42 checks, got %d", len(windows))
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

// A platform with no registered catalog would silently collect the wrong
// platform's evidence, so the registry stops there instead.
func TestChecksForUnknownPlatformPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("an unregistered platform should stop here")
		}
	}()
	checks.ChecksFor("plan9")
}

// Catalog invariants, locked here instead of in an init(): probe labels are
// unique within a fallback chain (the fallback note joins `skipped → current`,
// and a repeated label would present two indistinguishable tiers), head and
// line_limit are mutually exclusive (their truncation semantics differ), and
// rule and filter ids are unique within a check (a repeated filter id would fold
// two filters' hidden-line counts into one).
func TestCatalogInvariants(t *testing.T) {
	for _, catalog := range [][]*model.Check{checks.ChecksFor(model.Linux), checks.ChecksFor(model.Windows)} {
		ids := map[string]bool{}
		for _, check := range catalog {
			if ids[check.ID] {
				t.Errorf("duplicate check id: %s", check.ID)
			}
			ids[check.ID] = true
			labels := map[string]bool{}
			for _, probe := range check.Probes {
				if labels[probe.Label] {
					t.Errorf("check %s has a duplicate probe label: %s", check.ID, probe.Label)
				}
				labels[probe.Label] = true
				if probe.Head > 0 && probe.LineLimit > 0 {
					t.Errorf("check %s probe %s: Head and LineLimit are mutually exclusive", check.ID, probe.Label)
				}
			}
			rules := map[string]bool{}
			for _, rule := range check.Rules {
				if rules[rule.ID] {
					t.Errorf("check %s repeats rule id %s", check.ID, rule.ID)
				}
				rules[rule.ID] = true
			}
			filters := map[string]bool{}
			for _, filter := range check.Filters {
				if filters[filter.ID] {
					t.Errorf("check %s repeats filter id %s", check.ID, filter.ID)
				}
				filters[filter.ID] = true
			}
		}
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
