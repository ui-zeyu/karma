// File reads: the cat and tail tiers, as one file's body at a time.

package localfs

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrNotRegular is what a reader reports for a path that holds no bytes to give
// on its own: a FIFO, a device, a socket, or a directory. A caller that has a
// user-facing vocabulary of its own phrases the kind itself (cli.readError names
// the operand), so the kind travels as a value rather than as text to parse.
var ErrNotRegular = errors.New("not a regular file")

// Cat is the reader form of the file read: the bytes a file section carries —
// the file exactly as the kernel
// returned it, from karma's own read rather than the host's cat, so a preload
// hook on the host binary cannot reshape the answer.
//
// Only a regular file is read, and the open is the non-blocking one: a FIFO
// cannot park this process in open(2), and a path that is not a regular file is
// reported rather than read — `cat` on a FIFO blocks in coreutils too, and a
// command the operator names one operand to should say what it found. The
// collection tiers read such a path as empty instead (ReadRegular): a check
// answers with evidence rather than refusing.
func Cat(path string) ([]byte, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	return io.ReadAll(file)
}

// ReadRegular reads a whole file for an in-process tier, opening it without
// blocking (see openRegular): the fixed paths these tiers read — the utmp
// records, /etc/passwd, /etc/ld.so.preload, a boot config — are host-writable,
// and a FIFO planted at one of them would hang the collection with no way out
// but SIGKILL. A FIFO reads as empty here instead, which is the same answer an
// empty file gives.
func ReadRegular(path string) ([]byte, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

// Tail is the reader form of `tail -c n`: the file's last n bytes, or the whole
// file when it is smaller. The read is bounded by n, so a log that has grown
// for years costs what the window costs — and it starts exactly on the offset
// tail starts on, partial first line and all, so both sources see the same
// bytes. A path that is not a regular file is not a body and reports an error
// (the open is non-blocking, so a FIFO cannot hang it).
func Tail(path string, n int64) ([]byte, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	size := info.Size()
	if size > n {
		if _, err := file.Seek(size-n, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(file, n))
}

// ListFiles is a file list's own answer: the existing regular files of a path
// and glob word list, one path per line, in the collection's order. It is the
// in-process spelling of the sh source's `for f in …; do [ -f "$f" ] && echo
// "$f"; done`, so both sources name the same files in the same order.
func ListFiles(patterns []string) string {
	return strings.Join(ExpandFiles(patterns), "\n")
}

// ListDirs is a directory list's own answer: the directories the word list
// names, one path per line, globs expanded the way the target shell expands
// them.
func ListDirs(dirs []string) string {
	return strings.Join(ExpandDirs(dirs), "\n")
}

// ReadBody is one file's body for a file-list section: the file whole, or the
// transform's window over it (nil keeps it as read). A path that cannot be read
// is an empty body, the way the sh source's own read drops its error text.
func ReadBody(path string, transform func(string) string) string {
	text := ""
	// ReadRegular rather than os.ReadFile: these paths are host files, and the
	// shell counterpart skips a non-regular name outright.
	if body, err := ReadRegular(path); err == nil {
		text = string(body)
	}
	if transform != nil {
		text = transform(text)
	}
	return text
}

// TailLines keeps the last n lines of a body: the sh source's `tail -n N`,
// byte for byte, so a body whose last line carries no newline keeps none here
// either (the runner supplies the section's terminator). The window is found
// by scanning back for n line breaks, so a log that has grown for years costs
// the window rather than a line slice of the whole body.
func TailLines(n int) func(string) string {
	return func(text string) string {
		if text == "" || n <= 0 {
			return ""
		}
		// A trailing newline terminates the last line; it does not start an
		// empty one, which is why it is not counted as a line break here.
		end := len(text)
		if text[end-1] == '\n' {
			end--
		}
		start, seen := 0, 0
		for i := end - 1; i >= 0; i-- {
			if text[i] != '\n' {
				continue
			}
			seen++
			if seen == n {
				start = i + 1
				break
			}
		}
		return text[start:]
	}
}
