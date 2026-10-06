package checks_test

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"karma/internal/checks"
	"karma/internal/checks/linux"
	"karma/internal/model"
	"karma/internal/testkit"
)

func TestCatalogShape(t *testing.T) {
	linux := checks.ChecksFor(model.Linux)
	if len(linux) != 77 {
		t.Fatalf("the Linux catalog should hold 77 checks, got %d", len(linux))
	}
	windows := checks.ChecksFor(model.Windows)
	if len(windows) != 43 {
		t.Fatalf("the Windows catalog should hold 43 checks, got %d", len(windows))
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
// unique within one chain (the fallback note joins `skipped → current`, and a
// repeated label would present two indistinguishable tiers), and rule and filter
// ids are unique within a check (a repeated filter id would fold two filters'
// hidden-line counts into one). A tier's row cap is one value (model.RowCap), so
// the "shape or scan, never both" pair that used to need a rule here cannot be
// written down at all.
func TestCatalogInvariants(t *testing.T) {
	for _, catalog := range [][]*model.Check{checks.ChecksFor(model.Linux), checks.ChecksFor(model.Windows)} {
		ids := map[string]bool{}
		for _, check := range catalog {
			if ids[check.ID] {
				t.Errorf("duplicate check id: %s", check.ID)
			}
			ids[check.ID] = true
			labels := map[string]bool{}
			for _, step := range check.Steps {
				for _, probe := range step {
					if labels[probe.Label] {
						t.Errorf("check %s has a duplicate probe label: %s", check.ID, probe.Label)
					}
					labels[probe.Label] = true
				}
			}
			// A check with no tier on one channel would silently drop from that
			// channel's run.
			for _, ch := range []model.Channel{model.ChanLocal, model.ChanSSH, model.ChanTTYD} {
				if !slices.ContainsFunc(slices.Concat(check.Steps...), func(p model.Probe) bool {
					return p.InvocationFor(ch) != nil
				}) {
					t.Errorf("check %s has no tier for channel %d", check.ID, ch)
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

// A check's walk is one step per probe, and the only steps that hold several are
// the Windows registry fallbacks, where one process per key has to answer as a
// whole. A chain that quietly became an answer set would run its tiers together
// and present the first answer as the check's — dropping every later tier's
// evidence — which is exactly what a bulk edit of the catalog got wrong once.
func TestOnlyTheRegistryFallbacksShareAStep(t *testing.T) {
	for _, check := range checks.ChecksFor(model.Linux) {
		for index, step := range check.Steps {
			if len(step) != 1 {
				t.Errorf("%s step %d holds %d probes: a Linux chain is one probe per step", check.ID, index, len(step))
			}
		}
	}
	for _, check := range checks.ChecksFor(model.Windows) {
		for index, step := range check.Steps {
			if len(step) == 1 {
				continue
			}
			for _, probe := range step {
				argv, ok := probe.Inv.(model.Command)
				if !ok || len(argv.Argv) < 2 || argv.Argv[0] != "reg" || argv.Argv[1] != "query" {
					t.Errorf("%s step %d: %s shares a step with other probes (%+v)", check.ID, index, probe.Label, probe.Inv)
				}
			}
		}
	}
}

// The walk of two known checks, pinned: the number of steps is what decides which
// tier answers, so a regrouped catalog must fail here and not silently collect
// different evidence.
func TestKnownWalksKeepTheirSteps(t *testing.T) {
	cases := []struct {
		platform model.Platform
		id       string
		steps    []int // probes per step, in order
	}{
		{model.Linux, "uptime", []int{1, 1}},
		{model.Linux, "lsmod", []int{1, 1}},
		{model.Linux, "modules-load", []int{1}},
		{model.Linux, "accounts", []int{1}},
		{model.Windows, "run-keys", []int{1, 5}},
	}
	for _, c := range cases {
		check := testkit.CheckByID(t, checks.ChecksFor(c.platform), c.id)
		var got []int
		for _, step := range check.Steps {
			got = append(got, len(step))
		}
		if !slices.Equal(got, c.steps) {
			t.Errorf("%s: walk is %v probes per step, want %v", c.id, got, c.steps)
		}
	}
}

// Every /bin/sh script in the catalog passes sh -n: the syntax check for
// generated scripts is a test instead of a manual step. mtime is a dynamically
// built check, so a sample directory stands in for one.
func TestShellScriptsParse(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh, skipping the script syntax check")
	}
	var scripts []string
	for _, check := range checks.ChecksFor(model.Linux) {
		for _, step := range check.Steps {
			for _, probe := range step {
				if dual, ok := probe.Inv.(model.Dual); ok && dual.Script != "" {
					scripts = append(scripts, check.ID+": "+dual.Script)
				}
			}
		}
	}
	hunt := linux.HuntCheck([]string{"/tmp/demo", "/var/www"})
	for _, step := range hunt.Steps {
		for _, probe := range step {
			if dual, ok := probe.Inv.(model.Dual); ok && dual.Script != "" {
				scripts = append(scripts, hunt.ID+": "+dual.Script)
			}
		}
	}
	if len(scripts) == 0 {
		t.Fatal("the catalog should yield shell scripts")
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
