// The non-Linux stub of dmesg's native tier.

//go:build !linux

package native

import (
	"context"

	"karma/internal/model"
)

// Dmesg needs syslog(2); without it the tier is unavailable.
func Dmesg(ctx context.Context) (string, error) {
	return "", model.ErrTierUnavailable
}
