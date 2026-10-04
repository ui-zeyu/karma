package cli_test

import (
	"slices"
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
