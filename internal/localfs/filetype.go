// The file(1) classification, in process: the auth-binaries type check reads a
// file's head itself instead of running a dynamically linked file(1) whose libc
// an LD_PRELOAD hook can reshape. The ELF header is parsed by the standard
// library's debug/elf; the script and text fallbacks look at the first bytes the
// way file(1) does. Only the vocabulary the bin-not-elf rule grades has to match
// ("script", "ASCII text", "Unicode text"), so the words are file(1)'s and the
// extra detail file prints is left out.

package localfs

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

// FileRows renders the `== file` forensics section: one `path: words` line per
// existing file, in the order the caller gave — the order the list itself
// expresses, which is what the shell tier's `file $list` prints (file(1) reads
// its arguments in order) and what the verifier's own output expresses. LsRows
// sorts, because ls sorts its arguments; this section must not, or the two
// channels' `== file` sections would list the same rows in different orders.
//
// A path this process may not read reads "cannot open": file(1) names the reason
// there ("regular file, no read permission"), which is a recorded difference
// between the channels' rows for a file the collecting user cannot read.
func FileRows(files []string) string {
	var b strings.Builder
	for _, path := range files {
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		b.WriteString(path + ": " + fileTypeWords(path) + "\n")
	}
	return b.String()
}

// fileTypeWords describes one path with the words the bin-not-elf rule grades.
// A path that is not a regular file is named from its mode instead of read (the
// open is non-blocking, so a planted FIFO cannot hang this): file(1) spells
// those types from stat alone, and printing them keeps the local section equal
// to the ssh channel's, where the tool reports the same planted FIFO.
func fileTypeWords(path string) string {
	f, err := openRegular(path)
	if err != nil {
		return "cannot open"
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "cannot open"
	}
	if !info.Mode().IsRegular() {
		return specialWords(info.Mode())
	}
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

// specialWords spells the file types file(1) names from stat alone: the ones
// the local channel opens its own paths for, so a FIFO or device node planted
// at one of them is reported rather than followed.
func specialWords(mode os.FileMode) string {
	switch {
	case mode.IsDir():
		return "directory"
	case mode&os.ModeNamedPipe != 0:
		return "fifo (named pipe)"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0:
		return "character special"
	case mode&os.ModeDevice != 0:
		return "block special"
	}
	return "data"
}

// ProgramFile reports whether path is a file a package-verify divergence
// should name on its own: an ELF object (a binary, a shared library or a core
// file) or a path carrying an execute bit. Everything else is text or data
// that counts toward the directory it lives in. A path that is gone is not a
// program: its type is unknown, and the caller reports it as missing instead.
func ProgramFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if info.Mode()&0o111 != 0 {
		return true
	}
	return strings.HasPrefix(fileTypeWords(path), "ELF")
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
