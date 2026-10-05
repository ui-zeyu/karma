// native_filetype: the `file` classification done in process, so the
// auth-binaries type check no longer runs a dynamically linked file(1) whose
// libc an LD_PRELOAD hook can reshape. The ELF header is parsed by the
// standard library's debug/elf; the script and text fallbacks look at the
// first bytes the way file(1) does. Only the vocabulary the bin-not-elf rule
// grades has to match ("script", "ASCII text", "Unicode text"), so the words
// are file(1)'s and the extra detail file prints is left out.

package linux

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// fileHeadBytes is how much of a file the classifier reads.
const fileHeadBytes = 4096

// fileRows renders the `== file` forensics section: one `path: words` line per
// existing file, in the listing tier's sorted order.
func fileRows(files []string) string {
	sorted := sortedPaths(files)
	var b strings.Builder
	for _, path := range sorted {
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		b.WriteString(path + ": " + fileTypeWords(path) + "\n")
	}
	return b.String()
}

// fileTypeWords describes one path with the words the bin-not-elf rule grades.
func fileTypeWords(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "cannot open"
	}
	defer f.Close()
	buf := make([]byte, fileHeadBytes)
	n, _ := io.ReadFull(f, buf)
	head := buf[:n]
	switch {
	case bytes.HasPrefix(head, []byte("\x7fELF")):
		return elfWords(f)
	case bytes.HasPrefix(head, []byte("#!")):
		return scriptWords(head)
	}
	if words, ok := textWords(head); ok {
		return words
	}
	return "data"
}

// elfWords spells the ELF header the way file(1) opens that line. The reader is
// the whole file rather than the first block it was classified from: debug/elf
// resolves the section and program headers by offset, and every real binary
// keeps them past the first 4096 bytes — reading only the head left this
// function with the bare "ELF" fallback.
func elfWords(f io.ReaderAt) string {
	parsed, err := elf.NewFile(f)
	if err != nil {
		return "ELF"
	}
	defer parsed.Close()
	class := "32-bit"
	if parsed.Class == elf.ELFCLASS64 {
		class = "64-bit"
	}
	order := "LSB"
	if parsed.Data == elf.ELFDATA2MSB {
		order = "MSB"
	}
	kind := "executable"
	switch parsed.Type {
	case elf.ET_DYN:
		kind = "shared object"
	case elf.ET_REL:
		kind = "relocatable"
	case elf.ET_CORE:
		kind = "core file"
	}
	return fmt.Sprintf("ELF %s %s %s", class, order, kind)
}

// scriptWords spells a shebang file: file(1) prints the interpreter name
// followed by "script".
func scriptWords(head []byte) string {
	line, _, _ := bytes.Cut(head, []byte("\n"))
	interp := strings.TrimSpace(string(line[2:]))
	if i := strings.IndexAny(interp, " \t"); i >= 0 {
		interp = interp[:i]
	}
	kind := "script"
	if interp != "" {
		kind = interp + " script"
	}
	return "a " + kind + ", ASCII text executable"
}

// textWords classifies a non-ELF, non-shebang head as text when it is mostly
// printable and decodes as UTF-8 (a head cut mid-rune still counts).
func textWords(head []byte) (string, bool) {
	if !isMostlyPrintable(head) {
		return "", false
	}
	if isASCII(head) {
		return "ASCII text", true
	}
	if !utf8.Valid(trimPartialRune(head)) {
		return "", false
	}
	return "Unicode text, UTF-8 text", true
}

// isMostlyPrintable follows file(1)'s heuristic: a head whose control bytes
// stay under a few percent reads as text.
func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	bad := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c != 0x7f) {
			continue
		}
		bad++
	}
	return bad*100/len(b) < 5
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

// trimPartialRune drops up to three trailing bytes so a head truncated
// mid-rune still validates as UTF-8.
func trimPartialRune(b []byte) []byte {
	for i := 0; i < 3 && len(b) > 0; i++ {
		b = b[:len(b)-1]
		if utf8.Valid(b) {
			return b
		}
	}
	return b
}
