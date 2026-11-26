package cli

// The scope grammar's judgments: a domain word keeps every activation surface
// in judgment scope, an exclusion is exclusion-first, and a surface group
// expands to its surfaces and its domain.

import (
	"strings"
	"testing"

	"karma/internal/audit"
	"karma/internal/startup"
)

// TestDomainWordKeepsEverySurfaceInJudgmentScope pins the answer to "audit
// persistence": the filter's surface set stays nil, so every activation edge
// is judged and the ACTIVATION panel fills. An empty surface map here would
// silently judge nothing (this was a real bug).
func TestDomainWordKeepsEverySurfaceInJudgmentScope(t *testing.T) {
	parsed, err := parseScope([]string{"persistence"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.filter(audit.Info).Surfaces != nil {
		t.Error("a domain word must not name surfaces: an empty set judges none")
	}
}

func TestSurfaceExclusionIsExclusionFirst(t *testing.T) {
	parsed, err := parseScope([]string{"!profile"})
	if err != nil {
		t.Fatal(err)
	}
	surfaces := parsed.filter(audit.Info).Surfaces
	if surfaces["profile"] {
		t.Error("the excluded surface stayed on")
	}
	for _, surface := range startup.SurfaceWords() {
		if surface == "profile" {
			continue
		}
		if !surfaces[surface] {
			t.Errorf("!profile turned %s off too; an exclusion starts from every surface", surface)
		}
	}
}

func TestSurfaceGroupExpandsToSurfacesAndDomain(t *testing.T) {
	parsed, err := parseScope([]string{"boot"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.domains&audit.DomainPersistence == 0 {
		t.Errorf("the boot group carried no persistence domain: %b", parsed.domains)
	}
	for _, surface := range surfaceGroups["boot"] {
		if !parsed.surfaces[surface] {
			t.Errorf("the boot group did not turn on %s", surface)
		}
	}
	// The plan carries the same surface selection, so the collection reads
	// exactly what the judgment will read.
	plan := parsed.plan()
	for _, surface := range surfaceGroups["boot"] {
		if !plan.Surfaces[surface] {
			t.Errorf("the boot plan's surface set misses %s", surface)
		}
	}
}

func TestScopeGrammarErrors(t *testing.T) {
	if _, err := parseScope([]string{"bogus"}); err == nil || !strings.Contains(err.Error(), "unknown scope") {
		t.Errorf("an unknown word must be refused, got %v", err)
	}
	if _, err := parseScope([]string{"!"}); err == nil || !strings.Contains(err.Error(), "exclusion") {
		t.Errorf("a bare exclusion must be refused, got %v", err)
	}
}

func TestFilterCarriesTheSelection(t *testing.T) {
	parsed, err := parseScope([]string{"/var/www", "!/var/www/old", "/proc/33", "sshd.service", "persistence"})
	if err != nil {
		t.Fatal(err)
	}
	filter := parsed.filter(audit.High)
	if len(filter.Paths) != 1 || filter.Paths[0] != "/var/www" {
		t.Errorf("paths = %v", filter.Paths)
	}
	if len(filter.ExcludePaths) != 1 || filter.ExcludePaths[0] != "/var/www/old" {
		t.Errorf("exclusions = %v", filter.ExcludePaths)
	}
	if !filter.PIDs[33] {
		t.Errorf("pids = %v", filter.PIDs)
	}
	if !filter.Units["sshd.service"] {
		t.Errorf("units = %v", filter.Units)
	}
	if filter.MinSeverity != audit.High {
		t.Errorf("min severity = %s", filter.MinSeverity)
	}
}

// TestOffDomainsListTheUnjudgedDomains pins the masthead's honesty rule: a
// scoped run names the bounded domains it did not judge, and a bare run
// leaves the list empty.
func TestOffDomainsListTheUnjudgedDomains(t *testing.T) {
	parsed, err := parseScope([]string{"persistence"})
	if err != nil {
		t.Fatal(err)
	}
	off := offDomains(parsed.plan().Domains)
	if contains(off, "persistence") {
		t.Errorf("the judged domain is listed off: %v", off)
	}
	for _, word := range []string{"services", "processes", "network", "authority", "identity", "files", "packages", "web", "kernel"} {
		if !contains(off, word) {
			t.Errorf("off domains = %v, want %s listed", off, word)
		}
	}
	bare, err := parseScope(nil)
	if err != nil {
		t.Fatal(err)
	}
	if off := offDomains(bare.plan().Domains); len(off) != 0 {
		t.Errorf("a bare run lists off domains: %v", off)
	}
}
