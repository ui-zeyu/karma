// The catalog construction path: one function builds both platforms' checks, and
// the order it merges rules and filters in is the reading's own order — a rule is
// judged in declaration order, and a hidden line is counted under the first
// filter that hides it. Nothing else states that order, so it is pinned here.

package define

import (
	"slices"
	"testing"
	"time"

	"karma/internal/model"
)

// stubForm is a form the construction only has to carry, not to draw.
type stubForm struct{}

func (stubForm) Render(model.Block, model.RenderOptions) []string { return nil }

// names is a matcher list's ids, in order.
func names(matchers []model.Matcher) []string {
	return slices.Collect(func(yield func(string) bool) {
		for _, matcher := range matchers {
			if !yield(matcher.Name()) {
				return
			}
		}
	})
}

func filterIDs(filters []model.LineFilter) []string {
	return slices.Collect(func(yield func(string) bool) {
		for _, filter := range filters {
			if !yield(filter.ID) {
				return
			}
		}
	})
}

// A Linux check carries its own rules and filters first, then the platform's
// pack, then the global blank-line filter.
func TestCheckMergesItsOwnRulesAndFiltersFirst(t *testing.T) {
	check := LinuxCheck("probe", "Probe", model.AspectSystem,
		[]model.Step{{{Label: "probe", Inv: model.NewCommand("true")}}},
		CheckOpt{
			Rules:   []model.Matcher{model.NewRule("own-rule", `own`, model.High, "own")},
			Filters: []model.LineFilter{model.NewFilter("own-filter", `^own`, model.FilterDrop)},
		})
	if got := names(check.Rules); len(got) < 2 || got[0] != "own-rule" {
		t.Fatalf("the check's own rule comes first: %v", got)
	}
	if got := names(check.Rules[1:]); !slices.Equal(got, names(GlobalRules)) {
		t.Fatalf("the platform pack follows the check's own rules: %v", got)
	}
	if got := filterIDs(check.Filters); !slices.Equal(got, []string{"own-filter", "blank"}) {
		t.Fatalf("filters = %v, want the check's own then the blank filter", got)
	}
}

// The Windows catalog has no pack of its own yet, and Linux's dashes-shaped
// rules never reach it: a Windows check carries its own rules and the blank
// filter, and nothing else.
func TestWindowsCheckCarriesNoLinuxPack(t *testing.T) {
	check := WindowsCheck("probe", "Probe", model.AspectSystem,
		[]model.Step{{{Label: "probe", Inv: model.NewCommand("whoami")}}},
		CheckOpt{Rules: []model.Matcher{model.NewRule("own-rule", `own`, model.High, "own")}})
	if got := names(check.Rules); !slices.Equal(got, []string{"own-rule"}) {
		t.Fatalf("rules = %v, want the check's own alone", got)
	}
	if got := filterIDs(check.Filters); !slices.Equal(got, []string{"blank"}) {
		t.Fatalf("filters = %v, want the blank filter", got)
	}
	if check.Platform != model.Windows {
		t.Fatalf("platform = %q, want windows", check.Platform)
	}
}

// Everything a check declares about itself and its body arrives on the check:
// the walk, the presentation, and the run parameters.
func TestCheckOptLandsOnTheCheck(t *testing.T) {
	steps := []model.Step{{{Label: "probe", Inv: model.NewCommand("true")}}}
	sections := []model.SectionSyntax{{Title: "/etc/*", Syntax: model.SyntaxFstab}}
	shaped := func(string, string) *model.Shaped { return nil }
	check := LinuxCheck("probe", "Probe", model.AspectFilesystem, steps, CheckOpt{
		Syntax:        model.SyntaxTable,
		SectionSyntax: sections,
		Normalize:     shaped,
		Form:          stubForm{},
		Timeout:       5 * time.Second,
		ScanBytes:     4096,
	})
	if check.ID != "probe" || check.Title != "Probe" || check.Aspect != model.AspectFilesystem {
		t.Fatalf("identity: %+v", check)
	}
	if len(check.Steps) != 1 || check.Steps[0][0].Label != "probe" {
		t.Fatalf("walk: %+v", check.Steps)
	}
	if check.Syntax != model.SyntaxTable || !slices.Equal(check.SectionSyntax, sections) {
		t.Fatalf("presentation: %q %+v", check.Syntax, check.SectionSyntax)
	}
	if check.Normalize == nil || check.Form == nil {
		t.Fatalf("normalizer and form should be on the check: %+v", check)
	}
	if check.Timeout != 5*time.Second || check.ScanBytes != 4096 {
		t.Fatalf("run parameters: %v %d", check.Timeout, check.ScanBytes)
	}
	if check.Platform != model.Linux {
		t.Fatalf("platform = %q, want linux", check.Platform)
	}
}

// PrivateKeyRule is the one rule every platform reads: it is in the Linux pack,
// and a Windows check attaches it explicitly.
func TestPrivateKeyRuleIsInTheLinuxPack(t *testing.T) {
	if !slices.ContainsFunc(GlobalRules, func(rule model.Matcher) bool {
		return rule.Name() == PrivateKeyRule.Name()
	}) {
		t.Fatal("the Linux pack should carry the private-key rule")
	}
	if len(WindowsGlobalRules) != 0 {
		t.Fatalf("the Windows pack is empty today: %+v", WindowsGlobalRules)
	}
}
