//go:build !linux

package netdiag

import "context"

// Snapshot has no kernel interface outside Linux.
func Snapshot(context.Context) ([]Socket, error) { return nil, ErrUnavailable }

// Owners has no /proc to walk outside Linux.
func Owners(map[uint64]bool) map[uint64][]Owner { return nil }

// OwnersFor has no /proc to walk outside Linux.
func OwnersFor(map[uint64]bool, map[int]bool) map[uint64][]Owner { return nil }
