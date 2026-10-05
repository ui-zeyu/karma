// The non-Linux stub of dmesg's native tier.

//go:build !linux

package linux

import (
	"context"

	"karma/internal/model"
)

// nativeDmesg needs syslog(2); without it the tier is unavailable.
func nativeDmesg(ctx context.Context) (string, error) {
	return "", model.ErrTierUnavailable
}
