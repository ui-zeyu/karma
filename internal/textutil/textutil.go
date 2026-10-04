// Package textutil handles target-machine text line by line: splitting and iterating.
// Compatible with \r\n and \r (the target's mixed output may be CRLF); empty text has
// no lines. Shared by reading, clustering and fact parsing.
package textutil

import (
	"iter"
	"slices"
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
