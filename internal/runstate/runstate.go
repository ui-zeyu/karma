// Package runstate carries the reads one collection run shares between checks.
//
// Every check of a run inspects the same host, and a few of them want the same
// expensive view of it: the SUID and SGID checks, for instance, walk the whole
// filesystem with one traversal and differ only in the mode bit they look for.
// A store lets the first of them compute such a view and the others reuse it,
// so one pass over the filesystem serves both panels.
//
// The store lives in the context and is created per run (runner.RunCatalog),
// so its lifetime is exactly the run's. A check reached without one — a unit
// test calling a body directly — computes on its own, and nothing is cached.
package runstate

import (
	"context"
	"sync"
)

// Store is one run's memo table. It is safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	entries map[any]*entry
}

// entry is where the store's mutex stops helping: once keeps the computation to
// a single caller while any later caller of the same key blocks on it.
type entry struct {
	once sync.Once
	val  any
}

// storeKey is the context key; a private type keeps other packages' keys out.
type storeKey struct{}

// WithStore returns a context carrying an empty store. Call it once per run.
func WithStore(ctx context.Context) context.Context {
	return context.WithValue(ctx, storeKey{}, &Store{entries: map[any]*entry{}})
}

// From returns the run's store, or nil when the context carries none.
func From(ctx context.Context) *Store {
	store, _ := ctx.Value(storeKey{}).(*Store)
	return store
}

// Memo returns the value kept under key, computing it with compute the first
// time. Callers of the same key share one computation: the caller that wins
// runs compute and the rest wait for its result, so a shared read happens
// once per run. compute runs on the winning caller's goroutine, so the read it
// performs is bounded by that caller's context.
func Memo[T any](s *Store, key any, compute func() T) T {
	s.mu.Lock()
	slot, ok := s.entries[key]
	if !ok {
		slot = &entry{}
		s.entries[key] = slot
	}
	s.mu.Unlock()
	slot.once.Do(func() { slot.val = compute() })
	value, _ := slot.val.(T)
	return value
}
