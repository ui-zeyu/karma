// File reads: the cat and tail tiers, in the section shape the collection
// scripts print.

package localfs

import (
	"fmt"
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

// ReadSections mirrors script.ReadFiles: one "== path" section per existing
// regular file, in word-list order with glob results sorted; transform shapes
// the body (nil keeps the file as read). An unreadable file still prints its
// section with an empty body, like `cat "$f" 2>/dev/null`.
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
	}
	return b.String()
}

// TailLines keeps the last n lines of a body: the script tier's `tail -n N`.
func TailLines(n int) func(string) string {
	return func(text string) string {
		if text == "" {
			return ""
		}
		lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
		return strings.Join(lines, "\n") + "\n"
	}
}
