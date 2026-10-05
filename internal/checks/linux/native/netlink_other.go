// netlink's socket, address, neighbor, and route sources exist on Linux only;
// on every other platform each tier reports itself unavailable, so the local
// channel falls back to the host's own ss/ip/arp through the shell ladder.

//go:build !linux

package native

import (
	"context"

	"karma/internal/model"
)

func Ss(context.Context) (string, error)      { return "", model.ErrTierUnavailable }
func IPAddr(context.Context) (string, error)  { return "", model.ErrTierUnavailable }
func IPNeigh(context.Context) (string, error) { return "", model.ErrTierUnavailable }
func IPRoute(context.Context) (string, error) { return "", model.ErrTierUnavailable }
