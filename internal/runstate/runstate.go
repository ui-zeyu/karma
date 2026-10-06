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

// entry is one memo slot: the value and the completion signal a caller waits
// on. The signal is a channel rather than a sync.Once so the wait can be
// abandoned — the slot's owner may be parked in a syscall the tier boundary has
// already walked away from, and a wait that cannot be given up would cost every
// later caller its whole deadline.
type entry struct {
	done chan struct{}
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
//
// A waiting caller never waits past its own context. Giving up drops the slot,
// so the next caller starts a fresh computation instead of queueing behind the
// same stuck one; the abandoned owner keeps running and closes its own slot
// whenever — and if ever — its read returns. A slot that already holds its
// value is always used, even for a caller whose context has just ended: only a
// computation still in flight can be given up on.
func Memo[T any](ctx context.Context, s *Store, key any, compute func() T) T {
	s.mu.Lock()
	slot, shared := s.entries[key]
	if !shared {
		slot = &entry{done: make(chan struct{})}
		s.entries[key] = slot
	}
	s.mu.Unlock()

	if shared {
		select {
		case <-slot.done:
			value, _ := slot.val.(T)
			return value
		default:
		}
		select {
		case <-slot.done:
			value, _ := slot.val.(T)
			return value
		case <-ctx.Done():
			// Re-checked: the computation may have landed while this caller
			// was deciding to give up on it.
			select {
			case <-slot.done:
				value, _ := slot.val.(T)
				return value
			default:
			}
			s.mu.Lock()
			if s.entries[key] == slot {
				delete(s.entries, key)
			}
			s.mu.Unlock()
			return compute()
		}
	}
	value := compute()
	slot.val = value // written before the close, so waiters read it after
	close(slot.done)
	return value
}
