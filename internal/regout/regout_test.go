package regout_test

import (
	"strings"
	"testing"

	"karma/internal/regout"
)

const sampleBody = `HKEY_CURRENT_USER\Software\X\RunMRU
    MRUListEx    REG_BINARY    0C,00,00,00,01,00,00,00,\
        02,00,00,00,FF,FF,FF,FF
    Start_TrackEnabled    REG_DWORD    0x0
    Item 1    REG_SZ    hello world

HKEY_CURRENT_USER\Software\X\TypedPaths
    url1    REG_SZ    C:\Users\alice
`

func TestParseRegValues(t *testing.T) {
	values := regout.ParseRegValues(sampleBody)
	if len(values) != 4 {
		t.Fatalf("four values: %+v", values)
	}
	if got := values[0]; got.Name != "MRUListEx" || got.Type != "REG_BINARY" {
		t.Fatalf("first value wrong: %+v", got)
	}
	// The overlong binary wraps at a trailing backslash; the continuation merges in.
	if got, want := values[0].Data, "0C,00,00,00,01,00,00,00,02,00,00,00,FF,FF,FF,FF"; got != want {
		t.Fatalf("wrapped data should merge:\n got %s\nwant %s", got, want)
	}
	if got := values[1]; got.Name != "Start_TrackEnabled" || got.Data != "0x0" {
		t.Fatalf("dword row wrong: %+v", got)
	}
	if got := values[3]; got.Name != "url1" || got.Data != `C:\Users\alice` {
		t.Fatalf("second block wrong: %+v", got)
	}
}

func TestHexBytes(t *testing.T) {
	if got := string(regout.HexBytes("0C,00 FF")); got != "\x0c\x00\xff" {
		t.Fatalf("hex decode: %q", got)
	}
	if got := regout.HexBytes("nothex"); got != nil {
		t.Fatalf("unparsable text should give nil: %q", got)
	}
}

func TestRegBlocks(t *testing.T) {
	blocks := regout.RegBlocks(sampleBody)
	if len(blocks) != 2 {
		t.Fatalf("one block per key path: %+v", blocks)
	}
	if !strings.Contains(blocks[0].Key, "RunMRU") {
		t.Fatalf("the block key should be the subkey path: %q", blocks[0].Key)
	}
	if !strings.Contains(blocks[1].Body, "url1") {
		t.Fatalf("each block holds its own value rows: %+v", blocks[1])
	}
}

// Content before the first key path (a direct-run probe's raw body) is the
// preamble section, with an empty key name.
func TestRegBlocksPreamble(t *testing.T) {
	blocks := regout.RegBlocks("stray line\n    v    REG_SZ    d\nHKEY_X\n    a    REG_SZ    b\n")
	if len(blocks) != 2 || blocks[0].Key != "" || !strings.Contains(blocks[0].Body, "stray line") {
		t.Fatalf("the preamble should come back as an unnamed block: %+v", blocks)
	}
}
