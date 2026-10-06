package runstate

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// One traversal must serve every caller of a key: the checks that share a read
// run concurrently, so without single-flight they would all compute it.
func TestMemoComputesOnce(t *testing.T) {
	ctx := WithStore(context.Background())
	store := From(ctx)
	var calls atomic.Int64
	var wg sync.WaitGroup
	results := make([]int, 16)
	start := make(chan struct{})
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = Memo(ctx, store, "scan", func() int {
				calls.Add(1)
				return 42
			})
		}(i)
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("compute ran %d times, want 1", calls.Load())
	}
	for i, got := range results {
		if got != 42 {
			t.Fatalf("caller %d got %d, want 42", i, got)
		}
	}
}

// Distinct keys have their own values, and a second call for the same key does
// not recompute.
func TestMemoKeys(t *testing.T) {
	store := From(WithStore(context.Background()))
	calls := 0
	first := Memo(context.Background(), store, "a", func() string { calls++; return "A" })
	again := Memo(context.Background(), store, "a", func() string { calls++; return "again" })
	other := Memo(context.Background(), store, "b", func() string { calls++; return "B" })
	if first != "A" || again != "A" || other != "B" {
		t.Fatalf("values: %q %q %q", first, again, other)
	}
	if calls != 2 {
		t.Fatalf("compute ran %d times, want 2", calls)
	}
}

// A context without a store reports none, so a body still runs uncached.
func TestFromWithoutStore(t *testing.T) {
	if From(context.Background()) != nil {
		t.Fatal("a plain context should carry no store")
	}
}

// A slot that already holds its value is used even by a caller whose context
// has just ended: giving up is for a computation still in flight, never for a
// finished one.
func TestMemoUsesAFinishedSlotWithAnEndedContext(t *testing.T) {
	store := From(WithStore(context.Background()))
	if got := Memo(context.Background(), store, "scan", func() int { return 7 }); got != 7 {
		t.Fatalf("planted value = %d, want 7", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recomputed := false
	got := Memo(ctx, store, "scan", func() int { recomputed = true; return 8 })
	if got != 7 || recomputed {
		t.Fatalf("an ended context got %d (recomputed=%v), want the finished slot's 7", got, recomputed)
	}
}

// A caller whose deadline fires while the slot's owner is still computing walks
// away instead of inheriting the wait, and drops the slot so the next caller
// reads afresh rather than queueing behind the same stuck computation.
func TestMemoGivesUpOnAStuckOwner(t *testing.T) {
	store := From(WithStore(context.Background()))
	started := make(chan struct{})
	stuck := make(chan struct{})
	ownerDone := make(chan struct{})
	go func() {
		defer close(ownerDone)
		Memo(context.Background(), store, "scan", func() int {
			close(started)
			<-stuck
			return 1
		})
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if got := Memo(ctx, store, "scan", func() int { return 2 }); got != 2 {
		t.Fatalf("a caller out of time should answer from its own read, got %d", got)
	}
	if got := Memo(context.Background(), store, "scan", func() int { return 3 }); got != 3 {
		t.Fatalf("the dropped slot should be computed afresh, got %d", got)
	}

	close(stuck)
	<-ownerDone
}
