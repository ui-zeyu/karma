// Package regout parses reg.exe text output: value lines, merging of over-long
// wrapped lines, subkey chunking of the full `reg query /s` body, and hex data to
// bytes. facts and the Windows checks share the same row shape:
//
//	HKEY_CURRENT_USER\Software\...\RunMRU
//	    MRUList    REG_SZ    nmb
//	    0    REG_BINARY    0C,00,00,00,...,\
//	        00,00,00,00
//
// Value lines have a fixed 4-space indent, with 4 spaces between name and type; when
// REG_BINARY is over-long the line wraps at a trailing `\`, and continuation lines
// are indented 8 spaces or more.
package regout

import (
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/samber/lo"

	"karma/internal/textutil"
)

// Value is one value in reg query output: name, type, and the raw data after wrapped-line merging.
type Value struct {
	Name string
	Type string
	Data string
}

var (
	valueLine    = regexp.MustCompile(`^    (\S.*?)\s{4}(REG_[A-Z]+)\s*(.*)$`)
	continuation = regexp.MustCompile(`^ {8,}(\S.*)$`)
	keyLine      = regexp.MustCompile(`^(HKEY_.*)$`)
)

// ParseRegValues parses one reg query body into a value sequence; key-name lines (no indent) are ignored.
func ParseRegValues(body string) []Value {
	var values []Value
	current := (*Value)(nil)
	for line := range textutil.Lines(body) {
		if matched := valueLine.FindStringSubmatch(line); matched != nil {
			if current != nil {
				values = append(values, *current)
			}
			current = &Value{Name: matched[1], Type: matched[2], Data: strings.TrimSpace(matched[3])}
		} else if current != nil {
			if wrapped := continuation.FindStringSubmatch(line); wrapped != nil {
				joined := strings.TrimSuffix(current.Data, "\\") + strings.TrimSpace(wrapped[1])
				current.Data = joined
			}
		}
	}
	if current != nil {
		values = append(values, *current)
	}
	return values
}

// hexStrip cleans reg hex text: removes commas and spaces in one pass.
var hexStrip = strings.NewReplacer(",", "", " ", "")

// HexBytes converts reg's hex text (comma-separated) to bytes; unparsable gives empty.
func HexBytes(data string) []byte {
	out, err := hex.DecodeString(hexStrip.Replace(data))
	if err != nil {
		return nil
	}
	return out
}

// Block is one chunk after the full reg query /s body is split by subkey lines.
type Block struct {
	Key  string
	Body string
}

// RegBlocks splits the full `reg query /s` body by subkey lines (HKEY_ at column 0).
//
// Returns a sequence of (key path, block body); content before the first key path has
// an empty key name. Value lines have a fixed 4-space indent and key path lines are
// at column 0, so the two never mix.
func RegBlocks(body string) []Block {
	type group struct {
		key   string
		lines []string
	}
	var groups []group
	for line := range textutil.Lines(body) {
		if matched := keyLine.FindStringSubmatch(line); matched != nil {
			groups = append(groups, group{key: matched[1]})
			continue
		}
		if len(groups) == 0 {
			groups = append(groups, group{})
		}
		last := &groups[len(groups)-1]
		last.lines = append(last.lines, line)
	}
	return lo.Map(groups, func(g group, _ int) Block {
		return Block{Key: g.key, Body: strings.Join(g.lines, "\n")}
	})
}
