package model

import "testing"

func TestRequiredBinsDoesNotAliasArgv(t *testing.T) {
	cmd := NewCommand("ss", "-tunap")
	bins := (Probe{Inv: cmd}).RequiredBins()
	bins = append(bins, "extra")
	if cmd.Argv[1] != "-tunap" {
		t.Fatalf("RequiredBins wrote through to Argv: %v", cmd.Argv)
	}
	if len(bins) != 2 || bins[0] != "ss" {
		t.Fatalf("the derived result should be argv[0]: %v", bins)
	}
}
