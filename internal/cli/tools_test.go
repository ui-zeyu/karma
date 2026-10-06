// The built-in readers' failure sentences: they are the host tools' own
// wording, because that is what a script reading karma's output expects to
// parse, and a failed operand exits 1.
package cli

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReaderFailureSentences(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "gone.conf")
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"a directory operand", &fs.PathError{Op: "read", Path: dir, Err: errors.New("is a directory")},
			"cat " + dir + ": is a directory"},
		{"a missing file", &fs.PathError{Op: "open", Path: missing, Err: fs.ErrNotExist},
			"cat " + missing + ": no such file or directory"},
		{"a file without permission", &fs.PathError{Op: "open", Path: "/etc/shadow", Err: fs.ErrPermission},
			"cat /etc/shadow: permission denied"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := c.err.(*fs.PathError).Path
			var got error
			if c.name == "a directory operand" {
				got = catError(path, c.err)
			} else {
				got = readError("cat", path, c.err)
			}
			if got.Error() != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

// A directory operand reaches catError through the reader's own stat, and the
// failure leaves the process with status 1: a script that reads $? sees a
// failed read.
func TestCatOnADirectoryExitsWithOne(t *testing.T) {
	err := catError(t.TempDir(), os.ErrInvalid)
	if !strings.HasSuffix(err.Error(), "is a directory") {
		t.Fatalf("cat on a directory: %v", err)
	}
	if code := reportError(io.Discard, readerFailure(err)); code != 1 {
		t.Fatalf("a failed read should exit 1, got %d", code)
	}
	if err := readerFailure(nil); err != nil {
		t.Fatalf("a reader that read everything reports nothing, got %v", err)
	}
}
