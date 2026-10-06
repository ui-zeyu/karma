package windows

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// The constructors below hand-build binary in shell item format; field offsets correspond
// one-to-one with shellitem.go's parsing.

func u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func utf16ZBytes(text string) []byte {
	units := utf16.Encode([]rune(text))
	out := make([]byte, 0, len(units)*2+2)
	for _, u := range units {
		out = append(out, u16(u)...)
	}
	return append(out, 0, 0)
}

// dirItem 0x30 file/directory entry: short name, FAT modification time, and the Beef0004 extension
// block (creation/access times, UTF-16 long name).
func dirItem(isFile bool, short, longName string, mtime, ctime, atime uint32) []byte {
	shortBytes := append([]byte(short), 0)
	ext := []byte{}
	ext = append(ext, u16(0)...) // Size placeholder, backfilled at the end
	ext = append(ext, u16(9)...) // Version > 8: long name at offset 46
	ext = append(ext, 0x04, 0x00, 0xef, 0xbe)
	ext = append(ext, u32(ctime)...)
	ext = append(ext, u32(atime)...) // offset 8/12: creation, access
	ext = append(ext, u16(0)...)     // offset 16-19
	ext = append(ext, u16(0)...)
	ext = append(ext, u64(0)...) // MFTReference, offset 20-27
	for len(ext) < 46 {
		ext = append(ext, 0)
	}
	ext = append(ext, utf16ZBytes(longName)...)
	binary.LittleEndian.PutUint16(ext[0:2], uint16(len(ext)))

	item := []byte{}
	item = append(item, u16(0)...) // Size placeholder, backfilled at the end
	item = append(item, 0x30)
	kind := byte(0x00)
	if isFile {
		kind = 0x01
	}
	item = append(item, kind)                              // offset 3
	item = append(item, u32(0)...)                         // offset 4-7 file size
	item = append(item, u32(mtime)...)                     // offset 8 FAT modification time
	item = append(item, u16(uint16(len(shortBytes)+1))...) // offset 12 short name length
	item = append(item, shortBytes...)
	item = append(item, ext...)
	binary.LittleEndian.PutUint16(item[0:2], uint16(len(item)))
	return item
}

func u64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// guidBytes converts GUID text to binary (first three fields little-endian, last two big-endian).
func guidBytes(text string) []byte {
	clean := strings.ReplaceAll(strings.Trim(text, "{}"), "-", "")
	raw, err := hex.DecodeString(clean)
	if err != nil {
		panic(err)
	}
	out := make([]byte, 16)
	copy(out[0:4], []byte{raw[3], raw[2], raw[1], raw[0]})
	copy(out[4:6], []byte{raw[5], raw[4]})
	copy(out[6:8], []byte{raw[7], raw[6]})
	copy(out[8:16], raw[8:16])
	return out
}

func TestParseFileItem(t *testing.T) {
	mtime := uint32(0x5485C249) // modified
	ctime := uint32(0x5284B0D1) // created
	atime := uint32(0x20A35A43) // accessed: 2025-02-03 04:05:06
	item := parseShellItem(dirItem(false, "DESKTOP", "Desktop", mtime, ctime, atime))
	if item.kind != "dir" {
		t.Errorf("kind = %q, want dir", item.kind)
	}
	if item.name != "Desktop" {
		t.Errorf("name = %q, want extension-block long name Desktop", item.name)
	}
	want := fatTime(mtime)
	if !item.mtime.Equal(want) || item.mtime.IsZero() {
		t.Errorf("mtime = %v, want %v", item.mtime, want)
	}
	if !item.ctime.Equal(fatTime(ctime)) || !item.atime.Equal(fatTime(atime)) {
		t.Errorf("extension block times not decoded as FAT: %v / %v", item.ctime, item.atime)
	}

	file := parseShellItem(dirItem(true, "NOTE~1.TXT", "notes.txt", mtime, ctime, atime))
	if file.kind != "file" {
		t.Errorf("kind = %q, want file (offset 3 bit0)", file.kind)
	}
}

func TestFatTime(t *testing.T) {
	// 2024-03-01 12:34:00 → date is 44 year offset, March 1; time is 12:34:00 (half-second 0)
	date := uint16(44<<9 | 3<<5 | 1)
	clock := uint16(12<<11 | 34<<5)
	got := fatTime(uint32(date) | uint32(clock)<<16)
	want := time.Date(2024, 3, 1, 12, 34, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("fatTime = %v, want %v", got, want)
	}
	// absurd fields with month/day 0 are treated as zero
	if !fatTime(0).IsZero() {
		t.Errorf("fatTime(0) should be zero time")
	}
}

func TestParseRootAndDriveAndVolume(t *testing.T) {
	computer := guidBytes("20D04FE0-3AEA-1069-A2D8-08002B30309D")
	root := append([]byte{0x14, 0x00, 0x1f, 0x00}, computer...)
	item := parseShellItem(root)
	if item.kind != "root" || item.name != "MyComputer" {
		t.Errorf("root entry = %+v, want MyComputer", item)
	}

	drive := append([]byte{0x08, 0x00, 0x2f}, []byte("C:\\")...)
	drive = append(drive, 0)
	if got := parseShellItem(drive); got.kind != "drive" || got.name != "C:" {
		t.Errorf("drive entry = %+v, want C: after trailing separator normalization", got)
	}

	volume := append([]byte{0x18, 0x00, 0x20, 0x80}, computer...)
	volume = append(volume, []byte("Win11")...)
	volume = append(volume, 0)
	if got := parseShellItem(volume); got.kind != "volume" || got.name != "MyComputer" {
		t.Errorf("volume entry = %+v, want GUID name preference", got)
	}
}

func TestParseUnknownType(t *testing.T) {
	raw := append([]byte{0x10, 0x00, 0x99}, utf16ZBytes("Mystery")...)
	if item := parseShellItem(raw); item.kind != "unknown" {
		t.Errorf("unknown type should return unknown, got %q", item.kind)
	}
}

// hexValues assembles several name→binary pairs into the reg query value-line shape.
func hexValues(pairs ...[2]string) string {
	var lines []string
	for _, p := range pairs {
		lines = append(lines, "    "+p[0]+"    REG_BINARY    "+
			strings.ToUpper(hex.EncodeToString([]byte(p[1]))))
	}
	return strings.Join(lines, "\n")
}

func TestShellbagTimeline(t *testing.T) {
	rootKey := "HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"
	driveKey := rootKey + "\\0"
	usersKey := rootKey + "\\0\\0"

	computer := guidBytes("20D04FE0-3AEA-1069-A2D8-08002B30309D")
	rootItem := append([]byte{0x14, 0x00, 0x1f, 0x00}, computer...)
	driveItem := append([]byte{0x08, 0x00, 0x2f}, []byte("C:\\")...)
	driveItem = append(driveItem, 0)
	usersItem := dirItem(false, "USERS", "Users",
		0x5485C249, 0x5284B0D1, 0x20A35A43)

	body := rootKey + "\n" + hexValues([2]string{"0", string(rootItem)}) + "\n\n" +
		driveKey + "\n" + hexValues([2]string{"0", string(driveItem)}) + "\n\n" +
		usersKey + "\n" + hexValues([2]string{"1", string(usersItem)})

	shaped := shellbagNormalize("", body)
	if shaped == nil {
		t.Fatal("timeline is empty")
	}
	// Access time takes priority in descending order; entries without a time sort by text, and the root entry is a prefix of the path chain.
	want := strings.Join([]string{
		"2025-02-03 04:05:06  MyComputer\\C:\\Users",
		"MyComputer",
		"MyComputer\\C:",
	}, "\n")
	if shaped.Text != want {
		t.Errorf("timeline =\n%s\nwant\n%s", shaped.Text, want)
	}
}

// Unrecognized entries fall back to string extraction without losing the name.
func TestShellbagUnknownFallsBackToStrings(t *testing.T) {
	key := "HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"
	mystery := append([]byte{0x12, 0x00, 0x99, 0x00}, utf16ZBytes("MysteryPath")...)
	body := key + "\n" + hexValues([2]string{"0", string(mystery)})

	shaped := shellbagNormalize("", body)
	if shaped == nil || shaped.Text != "MysteryPath" {
		t.Errorf("unknown entry should fall back to string extraction yielding MysteryPath, got %+v", shaped)
	}
}

// Zero-time/empty input keeps old behavior: nothing extracted from the whole body returns nil (the check stays silent).
func TestShellbagEmptyReturnsNil(t *testing.T) {
	if shaped := shellbagNormalize("", ""); shaped != nil {
		t.Errorf("empty input should return nil, got %+v", shaped)
	}
}

// The third phase: nothing structural to read at all — every value name is
// non-numeric, so no shell item is built and no path chain exists — still yields
// what the whole body's binary values carry as UTF-16 text.
func TestShellbagWholeBodyFallback(t *testing.T) {
	key := `HKCU\Software\Classes\...\BagMRU`
	body := key + "\n" + hexValues(
		[2]string{"MRUListEx", "\x00\x00\x00\x00\xff\xff\xff\xff"},
		[2]string{"Comment", string(utf16ZBytes(`D:\stolen\vault`))},
	)
	shaped := shellbagNormalize("", body)
	if shaped == nil || shaped.Text != `D:\stolen\vault` {
		t.Fatalf("the whole-body fallback should extract the path, got %+v", shaped)
	}
}
