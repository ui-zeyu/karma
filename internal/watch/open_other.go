//go:build !linux

package watch

import (
	"context"
	"time"
)

// Open has no source outside Linux: the process and socket tables are kernel
// interfaces, and the fallbacks need them too.
func Open(context.Context, Family, Options) (Source, error) { return nil, ErrUnsupported }

// DefaultInterval is the poll cadence the command registers; the non-Linux
// build has no source to open, so the answer is the socket cadence.
func DefaultInterval(family Family) time.Duration {
	if family == FamilySocket {
		return 100 * time.Millisecond
	}
	return 50 * time.Millisecond
}
