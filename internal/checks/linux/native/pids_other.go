//go:build !linux

package native

import (
	"context"

	"karma/internal/model"
)

// HiddenPIDs cannot run without /proc: report the tier unavailable. The sh
// source's brute force is not on a local walk, so the check has nothing left
// and reads as Skipped on such a host.
func HiddenPIDs(context.Context) (string, error) {
	return "", model.ErrTierUnavailable
}
