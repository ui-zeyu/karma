// File reads: the cat and tail tiers, in the section shape the collection
// scripts print.

package localfs

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Cat is the reader form of the file read: the bytes ReadSections prints per
// section, without the "== path" header — the file exactly as the kernel
// returned it, from karma's own read rather than the host's cat, so a preload
// hook on the host binary cannot reshape the answer.
func Cat(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// Tail is the reader form of `tail -c n`: the file's last n bytes, or the whole
// file when it is smaller. The read is bounded by n, so a log that has grown
// for years costs what the window costs — and it starts exactly on the offset
// tail starts on, partial first line and all, so both channels see the same
// bytes. A directory is not a body and reports an error.
func Tail(path string, n int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	size := info.Size()
	if size > n {
		if _, err := file.Seek(size-n, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(file, n))
}

// ReadSections mirrors script.ReadFiles: one "== path" section per existing
// regular file, in word-list order with glob results sorted; transform shapes
// the body (nil keeps the file as read). An unreadable file still prints its
// section with an empty body, like `cat "$f" 2>/dev/null`.
//
// A body that does not end with a newline gets one, which is what the shell
// loop's `awk '{print}'` does: without the terminator the next `== path` header
// glues onto the last line and that section loses its title.
func ReadSections(patterns []string, transform func(string) string) string {
	var b strings.Builder
	for _, path := range ExpandFiles(patterns) {
		fmt.Fprintf(&b, "== %s\n", path)
		text := ""
		if body, err := os.ReadFile(path); err == nil {
			text = string(body)
		}
		if transform != nil {
			text = transform(text)
		}
		b.WriteString(text)
		if text != "" && !strings.HasSuffix(text, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// TailLines keeps the last n lines of a body: the script tier's `tail -n N`,
// byte for byte, so a body whose last line carries no newline keeps none here
// either (ReadSections supplies the section's terminator). The window is found
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
