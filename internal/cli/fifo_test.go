//go:build unix

package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A FIFO handed to -i is refused where it is named: the flags are parsed before
// any deadline exists, and loadIdentity's open would park the connection in
// open(2) with no signal able to break it.
func TestIdentityFileMustBeARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "planted")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newSSHCmd()
	if err := cmd.Flags().Set("identity", path); err != nil {
		t.Fatal(err)
	}
	_, err := buildSSHTransport(cmd.Flags(), "root@10.0.0.8")
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a FIFO identity file = %v; want it refused as a non-regular file", err)
	}
}
