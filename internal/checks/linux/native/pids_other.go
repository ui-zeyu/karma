//go:build !linux

package native

import (
	"context"

	"karma/internal/model"
)

// HiddenPIDs cannot run without /proc: report the tier unavailable and
// let the chain fall to the shell probe (which stays quiet for the same
// reason, so the whole check reads as Skipped on such hosts).
func HiddenPIDs(context.Context) (string, error) {
	return "", model.ErrTierUnavailable
}
