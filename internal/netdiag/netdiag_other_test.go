//go:build !linux

package netdiag

import (
	"context"
	"errors"
	"testing"
)

func TestUnavailable(t *testing.T) {
	if _, err := Snapshot(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Snapshot = %v, want ErrUnavailable", err)
	}
	if got := Owners(map[uint64]bool{1: true}); got != nil {
		t.Errorf("Owners = %v, want nil", got)
	}
}
