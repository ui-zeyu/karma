// tests for the in-process file(1) classification: the ELF header words, the
// shebang and text fallbacks, and the section rows.

package native

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalELF64 is a header-only ELF the standard library parses: no program
// or section headers, ET_DYN, x86-64.
func minimalELF64() []byte {
	h := make([]byte, 64)
	copy(h, "\x7fELF")
	h[4] = 2                                  // ELFCLASS64
	h[5] = 1                                  // ELFDATA2LSB
	h[6] = 1                                  // EV_CURRENT
	binary.LittleEndian.PutUint16(h[16:], 3)  // ET_DYN
	binary.LittleEndian.PutUint16(h[18:], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(h[20:], 1)  // EV_CURRENT
	binary.LittleEndian.PutUint16(h[52:], 64) // e_ehsize
	return h
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFileTypeWords(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"payload.elf", minimalELF64(), "ELF 64-bit LSB shared object"},
		{"run.sh", []byte("#!/bin/sh\necho hi\n"), "a /bin/sh script, ASCII text executable"},
		{"notes.txt", []byte("hello world\n"), "ASCII text"},
		{"utf8.txt", []byte("héllo wörld\n"), "Unicode text, UTF-8 text"},
		{"blob.bin", []byte{0x00, 0x01, 0x02, 0x00, 0xff}, "data"},
	}
	for _, c := range cases {
		path := writeTemp(t, c.name, c.data)
		if got := fileTypeWords(path); got != c.want {
			t.Errorf("fileTypeWords(%s) = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestFileTypeWordsFlagsScripts is the property the bin-not-elf rule grades: a
// script or text standing in for an auth binary has to read as one.
func TestFileTypeWordsFlagsScripts(t *testing.T) {
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"s.sh", []byte("#!/bin/bash\nid\n")},
		{"s.py", []byte("#!/usr/bin/python3\nprint(1)\n")},
		{"plain", []byte("just text\n")},
	} {
		words := fileTypeWords(writeTemp(t, c.name, c.data))
		if !strings.Contains(words, "script") && !strings.Contains(words, "text") {
			t.Errorf("%s classified %q; the rule would miss it", c.name, words)
		}
	}
}

func TestFileRows(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.sh"), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.elf"), minimalELF64(), 0o600); err != nil {
		t.Fatal(err)
	}
	out := fileRows([]string{
		filepath.Join(dir, "b.sh"),
		filepath.Join(dir, "a.elf"),
		filepath.Join(dir, "missing"),
	})
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 rows (the missing path drops), got %d:\n%s", len(lines), out)
	}
	if !strings.HasSuffix(lines[0], ": ELF 64-bit LSB shared object") {
		t.Errorf("rows are not sorted by path, or the ELF words are wrong: %q", lines[0])
	}
	if !strings.Contains(lines[1], "script") {
		t.Errorf("script row = %q", lines[1])
	}
}
