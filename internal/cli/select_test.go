package cli_test

import (
	"slices"
	"strings"
	"testing"

	"karma/internal/checks"
	"karma/internal/cli"
	"karma/internal/model"
)

func TestOtherPlatformAspectIsUnknown(t *testing.T) {
	if _, err := cli.SelectChecks([]string{"remote"}, checks.ChecksFor(model.Linux)); err == nil {
		t.Fatal("the Linux catalog must not know remote")
	}
	selected, err := cli.SelectChecks([]string{"remote"}, checks.ChecksFor(model.Windows))
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(selected))
	for i, check := range selected {
		ids[i] = check.ID
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"putty", "rdp-history", "remote-control"}) {
		t.Fatalf("the remote aspect: %v", ids)
	}
}

// A platform name selects every check of that platform; a platform the catalog
// does not carry is as unknown as a foreign aspect.
func TestPlatformSelector(t *testing.T) {
	all := checks.AllChecks()
	selected, err := cli.SelectChecks([]string{"windows"}, all)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != len(checks.ChecksFor(model.Windows)) {
		t.Fatalf("windows selected %d checks, want %d", len(selected), len(checks.ChecksFor(model.Windows)))
	}
	for _, check := range selected {
		if check.Platform != model.Windows {
			t.Fatalf("windows selected %s (%s)", check.ID, check.Platform)
		}
	}
	if _, err := cli.SelectChecks([]string{"windows"}, checks.ChecksFor(model.Linux)); err == nil {
		t.Fatal("the Linux catalog must not know windows")
	}
	// A platform combines with aspects and ids like any other selector word.
	mixed, err := cli.SelectChecks([]string{"persistence,sshd-config"}, all)
	if err != nil {
		t.Fatal(err)
	}
	var platforms map[model.Platform]bool
	for _, check := range mixed {
		if platforms == nil {
			platforms = map[model.Platform]bool{}
		}
		platforms[check.Platform] = true
	}
	if !platforms[model.Linux] || !platforms[model.Windows] {
		t.Fatalf("persistence should span both platforms: %v", platforms)
	}
}

// A leading ! excludes with the selector vocabulary: from the whole catalog
// when every word is an exclusion, from what the other words selected
// otherwise. Exclusion wins over selection, a typo fails with close matches,
// and a word list that leaves no checks is an error.
func TestExcludedSelectors(t *testing.T) {
	linux := checks.ChecksFor(model.Linux)
	pkgVerify, pkgAspect, procAspect := 0, 0, 0
	for _, check := range linux {
		if check.ID == "pkg-verify" {
			pkgVerify++
		}
		if check.Aspect == model.AspectPackage {
			pkgAspect++
		}
		if check.Aspect == model.AspectProcess {
			procAspect++
		}
	}
	if pkgVerify != 1 || pkgAspect < 2 || procAspect < 1 {
		t.Fatalf("catalog prerequisites: pkg-verify=%d package=%d process=%d", pkgVerify, pkgAspect, procAspect)
	}

	kept, err := cli.SelectChecks([]string{"!pkg-verify"}, linux)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != len(linux)-pkgVerify {
		t.Fatalf("excluding one check kept %d of %d", len(kept), len(linux))
	}

	kept, err = cli.SelectChecks([]string{"package,!pkg-verify"}, linux)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != pkgAspect-pkgVerify {
		t.Fatalf("package minus pkg-verify kept %d, want %d", len(kept), pkgAspect-pkgVerify)
	}

	kept, err = cli.SelectChecks([]string{"process", "!pkg-verify"}, linux)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != procAspect {
		t.Fatalf("excluding an unselected check changed the selection: %d of %d", len(kept), procAspect)
	}

	if _, err := cli.SelectChecks([]string{"!pkg-verfy"}, linux); err == nil || !strings.Contains(err.Error(), "unknown exclusion") {
		t.Fatalf("a typo should fail as an exclusion with close matches, got %v", err)
	}
	if _, err := cli.SelectChecks([]string{"!linux"}, linux); err == nil || !strings.Contains(err.Error(), "left no checks") {
		t.Fatalf("excluding everything should be an error, got %v", err)
	}
	if _, err := cli.SelectChecks([]string{"!"}, linux); err == nil {
		t.Fatal(`a bare "!" should be an error`)
	}
}
