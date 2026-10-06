// The non-blocking read helper over FIFO fixtures: a planted FIFO must read as
// evidence (or as an error), never as a hang. Every test here completing is
// part of the assertion — before the helper, each of these parked forever in
// open(2), with no timeout and no signal able to break it.

//go:build unix

package localfs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// fifo plants one FIFO and returns its path.
func fifo(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "planted")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadRegularOnAFifoReturnsEmpty(t *testing.T) {
	body, err := ReadRegular(fifo(t))
	if err != nil || len(body) != 0 {
		t.Fatalf("ReadRegular on a FIFO = %q, %v; want empty, nil", body, err)
	}
}

func TestReadRegularStillReadsARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(path, []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := ReadRegular(path)
	if err != nil || string(body) != "one\ntwo\n" {
		t.Fatalf("ReadRegular = %q, %v; want the file unchanged", body, err)
	}
}

func TestTailRejectsANonRegularFile(t *testing.T) {
	if _, err := Tail(fifo(t), 4096); err == nil {
		t.Fatal("Tail on a FIFO should report an error")
	}
}

func TestTailStillReadsTheWindowOfARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := Tail(path, 4)
	if err != nil || string(body) != "6789" {
		t.Fatalf("Tail = %q, %v; want the last four bytes", body, err)
	}
}

func TestFileRowsNamesAFifoInsteadOfFollowingIt(t *testing.T) {
	got := FileRows([]string{fifo(t)})
	if want := ": fifo (named pipe)\n"; len(got) < len(want) || got[len(got)-len(want):] != want {
		t.Fatalf("FileRows = %q; want it to end in %q", got, want)
	}
}
