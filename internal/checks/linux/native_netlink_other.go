// netlink's socket, address, neighbor, and route sources exist on Linux only;
// on every other platform each tier reports itself unavailable, so the local
// channel falls back to the host's own ss/ip/arp through the shell ladder.

//go:build !linux

package linux

import (
	"context"

	"karma/internal/model"
)

func nativeSs(context.Context) (string, error)      { return "", model.ErrTierUnavailable }
func nativeIPAddr(context.Context) (string, error)  { return "", model.ErrTierUnavailable }
func nativeIPNeigh(context.Context) (string, error) { return "", model.ErrTierUnavailable }
func nativeIPRoute(context.Context) (string, error) { return "", model.ErrTierUnavailable }
