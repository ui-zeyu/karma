package runstate

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
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
			results[i] = Memo(store, "scan", func() int {
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
	first := Memo(store, "a", func() string { calls++; return "A" })
	again := Memo(store, "a", func() string { calls++; return "again" })
	other := Memo(store, "b", func() string { calls++; return "B" })
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
