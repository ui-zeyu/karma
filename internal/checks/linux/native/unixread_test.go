// The utmp record reader over a planted FIFO: the local channel reads the
// record files itself, so a FIFO swapped in at one of them must read as an
// empty file, not park the check forever. The test finishing is the assertion.

//go:build unix

package native

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadUtmpRecordsOnAFifoReturnsPromptly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wtmp")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	recs, ok := readUtmpRecords(path)
	if !ok || len(recs) != 0 {
		t.Fatalf("readUtmpRecords on a FIFO = %d records, %v; want 0, true", len(recs), ok)
	}
}
