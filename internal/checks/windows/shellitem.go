// shell item structure parsing: each BagMRU value is one shell item (a PIDL entry), with names and
// timestamps at fixed offsets or in self-length/terminated fields, so structural reading avoids the
// fake CJK noise of sliding-window string extraction. The field layout follows [MS-SHLLINK] and the
// Velociraptor Windows.Forensics.Lnk profile; in an FAT time the low 16 bits are the date and the
// high 16 bits are the time (same as vtypes' FatTimestamp).

package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"karma/internal/textutil"
)

// shellItem is one parsed shell item; a zero time means the entry has no such time.
type shellItem struct {
	kind  string // root volume drive dir file network control unknown
	name  string
	mtime time.Time
	ctime time.Time
	atime time.Time
}

// parseShellItem parses one registry value (a complete entry with a 2-byte size prefix).
// Unrecognized types return unknown, and the caller falls back to string extraction.
func parseShellItem(data []byte) shellItem {
	if len(data) < 4 {
		return shellItem{kind: "unknown"}
	}
	kind := data[2]
	switch {
	case kind == 0x1f:
		return parseRootItem(data)
	case kind == 0x2f:
		// drive: the type byte is followed by a null-terminated ANSI drive-letter path; a trailing
		// separator is stripped uniformly ("C:\" → "C:"), so path joining never produces a double separator
		return shellItem{kind: "drive", name: strings.TrimSuffix(ansiString(data, 3), "\\")}
	case kind >= 0x20 && kind <= 0x2e:
		return parseVolumeItem(data)
	case kind >= 0x30 && kind <= 0x3f:
		return parseFileItem(data)
	case kind >= 0x40 && kind <= 0x4f:
		return shellItem{kind: "network", name: ansiString(data, 5)}
	case kind == 0x71 || kind == 0x77:
		return shellItem{kind: "control", name: guidName(data, 14)}
	default:
		return shellItem{kind: "unknown"}
	}
}

// parseRootItem 0x1f root entry: 16-byte GUID from offset 4; when byte4==0x2f,
// a 3-character user property name (a library's custom view) starts at offset 13.
func parseRootItem(data []byte) shellItem {
	if len(data) >= 16 && data[4] == 0x2f {
		return shellItem{kind: "root", name: string(data[13:16])}
	}
	return shellItem{kind: "root", name: guidName(data, 4)}
}

// parseVolumeItem 0x20 volume entry: offset 3 is flags, 0x80 means a 16-byte GUID starts at offset 4;
// the ANSI volume label follows the GUID (or starts at offset 4 when there is no GUID). The caller
// has established the 4-byte header.
func parseVolumeItem(data []byte) shellItem {
	name, labelAt := "", 4
	if data[3]&0x80 != 0 {
		name = guidName(data, 4)
		labelAt = 20
	}
	if label := ansiString(data, labelAt); name == "" {
		name = label
	}
	return shellItem{kind: "volume", name: name}
}

// parseFileItem 0x30-0x3f file/directory: offset 3 bit0 distinguishes file from directory,
// offset 8 is the FAT modification time, offset 14 a null-terminated ANSI short name; the Beef0004
// extension block carries creation/access times and the UTF-16 long name (long name wins--the short name is the 8.3 truncation).
func parseFileItem(data []byte) shellItem {
	it := shellItem{kind: "dir"}
	if len(data) < 12 {
		return shellItem{kind: "unknown"}
	}
	if data[3]&0x01 != 0 {
		it.kind = "file"
	}
	it.mtime = fatTime(binary.LittleEndian.Uint32(data[8:12]))
	name := ansiString(data, 14)
	if ext := beef0004(data); ext != nil {
		it.ctime, it.atime = ext.create, ext.access
		if ext.longName != "" {
			name = ext.longName
		}
	}
	it.name = name
	return it
}

// shellExt forensic times and long name from the Beef0004 extension block.
type shellExt struct {
	create   time.Time
	access   time.Time
	longName string
}

// beef0004 locates the extension block in the entry: search for the signature 04 00 ef be (u32
// 0xbeef0004 little-endian); the block starts 4 bytes before the signature (two u16s: Size and
// Version). The long name is at offset 42, or 46 when version > 8; null-terminated UTF-16.
func beef0004(data []byte) *shellExt {
	idx := bytes.Index(data, []byte{0x04, 0x00, 0xef, 0xbe})
	if idx < 4 {
		return nil
	}
	ext := data[idx-4:]
	if len(ext) < 16 {
		return nil
	}
	out := &shellExt{
		create: fatTime(binary.LittleEndian.Uint32(ext[8:12])),
		access: fatTime(binary.LittleEndian.Uint32(ext[12:16])),
	}
	longAt := 42
	if binary.LittleEndian.Uint16(ext[2:4]) > 8 {
		longAt = 46
	}
	if len(ext) > longAt {
		out.longName = utf16Z(ext[longAt:])
	}
	return out
}

// ansiString is a null-terminated ANSI string; without a terminator it reads to the end.
func ansiString(data []byte, off int) string {
	if off < 0 || off >= len(data) {
		return ""
	}
	return textutil.CStr(data[off:])
}

// utf16Z is a null-terminated UTF-16LE string.
func utf16Z(data []byte) string {
	var units []uint16
	for i := 0; i+1 < len(data); i += 2 {
		u := binary.LittleEndian.Uint16(data[i:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}

// guidName translates the 16-byte GUID at offset into a known folder name; unlisted ones keep the
// braced GUID form (a placeholder in the path chain).
func guidName(data []byte, off int) string {
	if off < 0 || off+16 > len(data) {
		return ""
	}
	text := guidText(data[off : off+16])
	if name, ok := KnownFolders["{"+text+"}"]; ok {
		return name
	}
	return "{" + text + "}"
}

// guidText converts a binary GUID to standard text form: first three fields little-endian, last two big-endian.
func guidText(raw []byte) string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		raw[3], raw[2], raw[1], raw[0],
		raw[5], raw[4],
		raw[7], raw[6],
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15])
}

// fatTime MS-DOS date/time: low 16 bits are the date (15-9 year-1980, 8-5 month, 4-0 day),
// high 16 bits are the time (15-11 hour, 10-5 minute, 4-0 half-second). Absurd fields (month 0,
// day 0, etc.) are treated as a zero time; the year and day fields cannot leave their range,
// the masks already bound them.
func fatTime(v uint32) time.Time {
	date, clock := v&0xFFFF, v>>16
	year := int(date>>9) + 1980
	month := int(date>>5) & 0xF
	day := int(date & 0x1F)
	if month < 1 || month > 12 || day < 1 {
		return time.Time{}
	}
	return time.Date(year, time.Month(month), day,
		int(clock>>11), int(clock>>5)&0x3F, int(clock&0x1F)*2, 0, time.UTC)
}
