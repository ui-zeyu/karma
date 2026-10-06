// Package textutil handles target-machine text: the line splitting and iteration,
// and the C strings the kernel's own structs carry. Compatible with \r\n and \r (the
// target's mixed output may be CRLF); empty text has no lines. Shared by reading,
// clustering and fact parsing.
package textutil

import (
	"iter"
	"slices"
	"strings"
)

// Lines iterates text by line: \n, \r and \r\n are all line boundaries; a trailing
// newline does not produce an extra empty line, and blank lines in the middle of the
// text are kept. Empty text has no lines. Splitting only on \n would leave \r at line
// ends, skewing filter counts and line numbers.
func Lines(text string) iter.Seq[string] {
	return func(yield func(string) bool) {
		start := 0
		for i := 0; i < len(text); i++ {
			advance, boundary := 0, false
			switch text[i] {
			case '\n':
				advance, boundary = 1, true
			case '\r':
				advance, boundary = 1, true
				if i+1 < len(text) && text[i+1] == '\n' {
					advance = 2
				}
			}
			if !boundary {
				continue
			}
			if !yield(text[start:i]) {
				return
			}
			i += advance - 1
			start = i + 1
		}
		if start < len(text) {
			yield(text[start:])
		}
	}
}

// CollectLines is the collecting version of Lines.
func CollectLines(text string) []string {
	return slices.Collect(Lines(text))
}

// CString reads the NUL-terminated string a fixed-size C field holds: uname(2)'s
// utsname spells its fields int8 on some architectures and byte on others, so the
// reader is generic over the two, and it stops at the terminator rather than at the
// field's end. The trailing blanks some kernels pad a field with are trimmed.
func CString[T ~int8 | ~byte](field []T) string {
	var b strings.Builder
	for _, c := range field {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return strings.TrimSpace(b.String())
}
