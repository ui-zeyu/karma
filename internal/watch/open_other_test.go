//go:build !linux

package watch

import (
	"context"
	"errors"
	"testing"
)

func TestOpenUnsupported(t *testing.T) {
	if _, err := Open(context.Background(), FamilyProcess, Options{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Open = %v, want ErrUnsupported", err)
	}
}
