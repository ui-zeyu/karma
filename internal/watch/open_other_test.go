//go:build !linux

package watch

import (
	"errors"
	"testing"
)

func TestOpenUnsupported(t *testing.T) {
	if _, err := Open(FamilyProcess, Options{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Open = %v, want ErrUnsupported", err)
	}
}
