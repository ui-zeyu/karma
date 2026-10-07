// netlink's socket, address, neighbor, and route sources exist on Linux only; on
// every other platform each tier reports itself unavailable, so the check's
// ladder falls to the host tool its next tier names (ifconfig, route, netstat,
// arp) or skips what is left. The sh source's own spellings are not on a local
// walk: a local run reads with the native source.

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
