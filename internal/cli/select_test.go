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
