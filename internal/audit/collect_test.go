package audit

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// TestCollectLocalReportsTheStages pins the progress vocabulary and its
// order: the package catalog, the startup surfaces, the plan's registry
// modules in collection order, and the content ledger last.
func TestCollectLocalReportsTheStages(t *testing.T) {
	var stages []string
	snapshot, err := CollectLocal(context.Background(), Plan{Domains: DomainBase | DomainIdentity}, func(stage string) {
		stages = append(stages, stage)
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if snapshot == nil {
		t.Fatal("nil snapshot")
	}
	want := []string{"catalog", "startup", "identity", "ledger"}
	if !slices.Equal(stages, want) {
		t.Fatalf("stages = %v, want %v", stages, want)
	}
}

// TestCollectLocalWithoutAReporterRuns pins the nil-progress path: a caller
// that does not ask for progress still gets the snapshot.
func TestCollectLocalWithoutAReporterRuns(t *testing.T) {
	snapshot, err := CollectLocal(context.Background(), Plan{Domains: DomainBase | DomainIdentity}, nil)
	if err != nil || snapshot == nil {
		t.Fatalf("collect with nil progress: snapshot=%v err=%v", snapshot, err)
	}
}

// TestCollectLocalStopsOnCancel pins the interrupt answer: the snapshot keeps
// what was read, the error says why it stopped, and the ledger stage (the
// second of table building and hashing) is skipped.
func TestCollectLocalStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stages []string
	snapshot, err := CollectLocal(ctx, Plan{Domains: DomainBase | DomainIdentity}, func(stage string) {
		stages = append(stages, stage)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if snapshot == nil {
		t.Fatal("nil snapshot")
	}
	want := []string{"catalog", "startup"}
	if !slices.Equal(stages, want) {
		t.Fatalf("stages = %v, want %v", stages, want)
	}
}
