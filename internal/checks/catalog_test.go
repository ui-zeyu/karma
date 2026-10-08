package checks_test

import (
	"slices"
	"testing"

	"karma/internal/checks"
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
			if rule.Name() == "reverse-shell-dev-tcp" {
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
// hidden-line counts into one). A tier's row cap is one value (model.RowCap):
// Shape or Scan, never a pair of fields to keep apart.
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
				// A step with no probe has nothing to run and no label to name; a
				// probe with neither an invocation nor a file list is a walk that
				// would stop in silence.
				if len(step) == 0 {
					t.Errorf("check %s has an empty step", check.ID)
				}
				// One step is one tier, so its parts share a label on purpose; two
				// steps that shared one would present two indistinguishable tiers in
				// the skip chain.
				stepLabels := map[string]bool{}
				for _, probe := range step {
					switch {
					case probe.Inv == nil && probe.Files == nil:
						t.Errorf("check %s probe %s carries no invocation", check.ID, probe.Label)
					case probe.Inv != nil && probe.Files != nil:
						t.Errorf("check %s probe %s carries both an invocation and a file list", check.ID, probe.Label)
					case probe.Files != nil && (probe.Files.List == nil || probe.Files.Read == nil):
						t.Errorf("check %s probe %s has an incomplete file list", check.ID, probe.Label)
					}
					stepLabels[probe.Label] = true
				}
				for label := range stepLabels {
					if labels[label] {
						t.Errorf("check %s has a duplicate probe label: %s", check.ID, label)
					}
					labels[label] = true
				}
			}
			rules := map[string]bool{}
			for _, rule := range check.Rules {
				if rules[rule.Name()] {
					t.Errorf("check %s repeats rule id %s", check.ID, rule.Name())
				}
				rules[rule.Name()] = true
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

// A step is one tier: its probes answer as a whole, so they belong to the same
// source, and a step that mixed the two would run one source's tier beside the
// other's and present the pair as one answer. A chain that quietly became an
// answer set would run its tiers together and present the first answer as the
// check's — dropping every later tier's evidence — which is what the label
// uniqueness above and this source rule pin together.
func TestEachStepIsOneTiersSet(t *testing.T) {
	for _, catalog := range [][]*model.Check{checks.ChecksFor(model.Linux), checks.ChecksFor(model.Windows)} {
		for _, check := range catalog {
			for index, step := range check.Steps {
				if len(step) == 0 {
					continue
				}
				source := model.SourceNative
				if step[0].Runs(model.SourceSh) && !step[0].Runs(model.SourceNative) {
					source = model.SourceSh
				}
				for _, probe := range step {
					if !probe.Runs(source) {
						t.Errorf("%s step %d mixes sources: %s does not run in %q",
							check.ID, index, probe.Label, source)
					}
				}
			}
		}
	}
}

// Every Linux check declares both sources' readings: the native source's own
// body (or a command it runs in place), and the sh source's spelling of the same
// evidence. A check that lost one side would answer nothing on the source that
// asked for it — silently, since a walk with no tier of that source is Skipped —
// which is what this pins.
func TestEveryLinuxCheckAnswersBothSources(t *testing.T) {
	for _, check := range checks.ChecksFor(model.Linux) {
		if len(check.StepsFor(model.SourceNative)) == 0 {
			t.Errorf("%s has no native-source tier", check.ID)
		}
		if len(check.StepsFor(model.SourceSh)) == 0 {
			t.Errorf("%s has no sh-source tier", check.ID)
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
		{model.Linux, "uptime", []int{1, 1, 1, 1}},
		{model.Linux, "lsmod", []int{1, 1, 1, 1}},
		{model.Linux, "modules-load", []int{1, 1}},
		{model.Linux, "accounts", []int{1, 1}},
		{model.Windows, "run-keys", []int{6, 5}},
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
