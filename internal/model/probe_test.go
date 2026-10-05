package model

import (
	"context"
	"testing"
)

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

func TestInvocationForPicksTheChannelBranch(t *testing.T) {
	both := Probe{Label: "scan", Inv: Dual{
		Run:    func(context.Context) (string, error) { return "", nil },
		Script: ":",
	}}
	if both.InvocationFor(ChanLocal) == nil || both.InvocationFor(ChanSSH) == nil {
		t.Fatal("a tier with both branches exists on both channels")
	}
	sshOnly := Probe{Label: "walk", Inv: Dual{Script: ":"}}
	if sshOnly.InvocationFor(ChanLocal) != nil {
		t.Fatal("a Dual without Run must not run on the local channel")
	}
	if sshOnly.InvocationFor(ChanSSH) == nil {
		t.Fatal("a Dual with Script runs on the ssh channel")
	}
	plain := Probe{Label: "ss", Inv: NewCommand("ss", "-tunap")}
	if _, ok := plain.InvocationFor(ChanLocal).(Command); !ok {
		t.Fatal("a command tier exists on the local channel as itself")
	}
	if _, ok := plain.InvocationFor(ChanSSH).(Command); !ok {
		t.Fatal("a command tier exists on the ssh channel as itself")
	}
}
