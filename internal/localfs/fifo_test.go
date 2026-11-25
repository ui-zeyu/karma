// The non-blocking read helper over FIFO fixtures: a planted FIFO must read as
// evidence (or as an error), never as a hang. Every test here completing is
// part of the assertion — before the helper, each of these parked forever in
// open(2), with no timeout and no signal able to break it.

//go:build unix

package localfs

import (
	"errors"
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

func TestCatRefusesAFifoWithoutBlocking(t *testing.T) {
	path := fifo(t)
	if _, err := Cat(path); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("Cat on a FIFO = %v; want ErrNotRegular", err)
	}
}

func TestCatStillReadsARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(path, []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := Cat(path)
	if err != nil || string(body) != "one\ntwo\n" {
		t.Fatalf("Cat = %q, %v; want the file unchanged", body, err)
	}
}

// A symlink to a regular file is the operand the operator means: the kind is
// read from what the link resolves to, not from the link itself.
func TestCatReadsThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "plain")
	if err := os.WriteFile(target, []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	body, err := Cat(link)
	if err != nil || string(body) != "body" {
		t.Fatalf("Cat through a symlink = %q, %v; want the target's bytes", body, err)
	}
}
