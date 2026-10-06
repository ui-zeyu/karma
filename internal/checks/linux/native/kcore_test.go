// The module-memory dig behind the rows: the regions nothing explains are read
// out of the kernel's core file, and only a module-shaped signature in them is
// reported. These tests drive that read from a synthetic core file — a header and
// one PT_LOAD segment per region, the way /proc/kcore maps the kernel — so the
// VA-to-offset arithmetic, the bounds and the signature precision are all pinned
// without a kernel that has a hidden module in it.

package native

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"karma/internal/script"
)

// kitNames is the shape the check's pattern has, with two names of the catalog so
// this package's tests carry no dependency on the catalog package.
var kitNames = regexp.MustCompile(`\b(?:diamorphine|reptile)(?:[_-]\w+)*\b`)

// coreSegment is one PT_LOAD segment of a synthetic core: the virtual address it
// maps and the bytes it maps there.
type coreSegment struct {
	vaddr   uint64
	payload []byte
}

// writeCore writes a minimal ELF64 core file whose program headers map the given
// segments. Only what debug/elf reads is filled in: the identification, the
// program header table, and one payload per segment at its own file offset.
func writeCore(t *testing.T, segments ...coreSegment) string {
	t.Helper()
	const (
		ehdrSize = 64
		phdrSize = 56
	)
	offset := uint64(ehdrSize + phdrSize*len(segments))
	body := make([]byte, offset)
	binary.LittleEndian.PutUint32(body[0:], 0x464c457f) // "\x7fELF"
	body[4] = byte(elf.ELFCLASS64)
	body[5] = byte(elf.ELFDATA2LSB)
	body[6] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(body[16:], uint16(elf.ET_CORE))
	binary.LittleEndian.PutUint16(body[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(body[20:], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(body[32:], ehdrSize)
	binary.LittleEndian.PutUint16(body[52:], ehdrSize)
	binary.LittleEndian.PutUint16(body[54:], phdrSize)
	binary.LittleEndian.PutUint16(body[56:], uint16(len(segments)))
	for index, segment := range segments {
		phdr := body[ehdrSize+index*phdrSize:]
		binary.LittleEndian.PutUint32(phdr[0:], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint32(phdr[4:], 5) // PF_R|PF_X
		binary.LittleEndian.PutUint64(phdr[8:], offset)
		binary.LittleEndian.PutUint64(phdr[16:], segment.vaddr)
		binary.LittleEndian.PutUint64(phdr[24:], segment.vaddr)
		binary.LittleEndian.PutUint64(phdr[32:], uint64(len(segment.payload)))
		binary.LittleEndian.PutUint64(phdr[40:], uint64(len(segment.payload)))
		binary.LittleEndian.PutUint64(phdr[48:], 0x1000)
		body = append(body, segment.payload...)
		offset += uint64(len(segment.payload))
	}
	path := filepath.Join(t.TempDir(), "kcore")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// region is one row's region as the join hands it to the dig: the range spelled
// the way /proc/vmallocinfo writes it, and the same range as numbers.
func region(vaddr uint64, size int, class string) script.UnownedRegion {
	return script.UnownedRegion{
		Range:  fmt.Sprintf("%#x-%#x", vaddr, vaddr+uint64(size)),
		Start:  vaddr,
		End:    vaddr + uint64(size),
		Size:   size,
		Caller: class,
	}
}

// The measured shape: a hidden module's region carries its build path, the name
// the loader gave it and the placeholder every module has — while the symbol names
// in the same bytes are not signatures on their own.
func TestModuleImagesNamesTheModuleBehindAnUnexplainedRegion(t *testing.T) {
	payload := []byte("\x00/home/lab/Diamorphine/diamorphine.c\x00diamorphine\x00" +
		"module_hide\x00hacked_getdents64\x00resolve_sym\x00__this_module\x00evil_secret.ko\x00\x00")
	core := writeCore(t, coreSegment{vaddr: 0xffff8000017c5000, payload: payload})
	rows := ModuleImages(core, []script.UnownedRegion{region(0xffff8000017c5000, len(payload), "module")}, kitNames)
	if len(rows) != 1 {
		t.Fatalf("the dig rendered %d rows, want 1: %v", len(rows), rows)
	}
	for _, want := range []string{"IMAGE 0xffff8000017c5000", "size ", "name:diamorphine",
		"source:/home/lab/Diamorphine/diamorphine.c", "marker:__this_module", "file:evil_secret.ko"} {
		if !strings.Contains(rows[0], want) {
			t.Errorf("the row should carry %q:\n%s", want, rows[0])
		}
	}
	for _, unwanted := range []string{"module_hide", "resolve_sym", "hacked_getdents64"} {
		if strings.Contains(rows[0], unwanted) {
			t.Errorf("a bare symbol name is not a signature, but the row carries %q:\n%s", unwanted, rows[0])
		}
	}
}

// One row carries at most coreValuesCap signatures and says how many it left out,
// so a symbol-dense image cannot turn one row into a wall of text.
func TestModuleImagesCapsTheSignaturesOneRowCarries(t *testing.T) {
	payload := []byte("diamorphine_secret\x00diamorphine_cleanup\x00/tmp/build/a/hide.c\x00" +
		"/tmp/build/b/other.h\x00/tmp/build/c/third.c\x00kit.ko\x00a.ko\x00__this_module\x00\x00")
	core := writeCore(t, coreSegment{vaddr: 0xffff8000017c5000, payload: payload})
	rows := ModuleImages(core, []script.UnownedRegion{region(0xffff8000017c5000, len(payload), "module")}, kitNames)
	if len(rows) != 1 {
		t.Fatalf("the dig rendered %d rows, want 1: %v", len(rows), rows)
	}
	fields := strings.Fields(rows[0])
	signatures := 0
	if last := fields[len(fields)-1]; strings.HasPrefix(last, "+") {
		if extra := last[1:]; extra == "0" {
			t.Errorf("a capped row should not say +0: %q", rows[0])
		}
	} else {
		t.Errorf("the row should end with the count it left out when it caps: %q", rows[0])
	}
	for _, field := range fields {
		if strings.Contains(field, ":") {
			signatures++
		}
	}
	if signatures != coreValuesCap {
		t.Errorf("the row carried %d signatures, want %d:\n%s", signatures, coreValuesCap, rows[0])
	}
}

// The bytes a 6.10+ kernel's anonymous JIT region is full of: instruction
// encodings that a printable-run scan reads as text. They must not produce a row.
func TestModuleImagesStaysQuietOnInstructionBytes(t *testing.T) {
	payload := []byte("SAUAVAW1\x00A_A^A][\x00SAUAVH\x00SAUAVH\x00SAUAVAW1\x00A_A^A][\x00")
	core := writeCore(t, coreSegment{vaddr: 0xffffffffc0366000, payload: payload})
	if rows := ModuleImages(core, []script.UnownedRegion{region(0xffffffffc0366000, len(payload), "shared")}, kitNames); len(rows) != 0 {
		t.Errorf("instruction bytes produced %v", rows)
	}
}

// A word that merely starts with a catalog name is not that name: the separator
// continuation is what refuses reptilian while accepting diamorphine_secret, the
// literal Diamorphine hides files by.
func TestModuleImagesRefusesAWordThatMerelyStartsWithAName(t *testing.T) {
	plain := []byte("reptilian\x00\x00")
	core := writeCore(t, coreSegment{vaddr: 0xffff8000017c5000, payload: plain})
	if rows := ModuleImages(core, []script.UnownedRegion{region(0xffff8000017c5000, len(plain), "module")}, kitNames); len(rows) != 0 {
		t.Errorf("reptilian produced %v", rows)
	}
	separated := []byte("diamorphine_secret\x00\x00")
	core = writeCore(t, coreSegment{vaddr: 0xffff8000017c5000, payload: separated})
	rows := ModuleImages(core, []script.UnownedRegion{region(0xffff8000017c5000, len(separated), "module")}, kitNames)
	if len(rows) != 1 || !strings.Contains(rows[0], "name:diamorphine_secret") {
		t.Errorf("the kit's own literal should be a signature: %v", rows)
	}
}

// Every way of not reading is the same answer, no rows: a core that is not there,
// a region the core does not map, a region with nothing in it, and a row whose
// range could not be parsed.
func TestModuleImagesIsQuietWhenItCannotRead(t *testing.T) {
	payload := []byte("/home/lab/Diamorphine/diamorphine.c\x00__this_module\x00")
	core := writeCore(t, coreSegment{vaddr: 0xffff8000017c5000, payload: payload})
	cases := []struct {
		name    string
		core    string
		regions []script.UnownedRegion
	}{
		{"no core file", filepath.Join(t.TempDir(), "absent"), []script.UnownedRegion{region(0xffff8000017c5000, len(payload), "module")}},
		{"no core path", "", []script.UnownedRegion{region(0xffff8000017c5000, len(payload), "module")}},
		{"no region", core, nil},
		{"a region the core does not map", core, []script.UnownedRegion{region(0xffffffffc0000000, 4096, "shared")}},
		{"a region with nothing in it", core, []script.UnownedRegion{region(0xffff800002000000, 8192, "module")}},
		{"a range that did not parse", core, []script.UnownedRegion{{Range: "junk", Size: 4096, Caller: "module"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rows := ModuleImages(tc.core, tc.regions, kitNames); len(rows) != 0 {
				t.Errorf("the dig produced %v", rows)
			}
		})
	}
}

// The dig reads through the segment that covers the region, not the file's start:
// the region below lives in the second segment, at its own file offset.
func TestModuleImagesReadsThroughTheCoveringSegment(t *testing.T) {
	first := []byte("nothing to see here but text\x00")
	second := []byte("/tmp/build/kit/hide.c\x00__this_module\x00")
	core := writeCore(t,
		coreSegment{vaddr: 0xffff800001000000, payload: first},
		coreSegment{vaddr: 0xffff800002000000, payload: second},
	)
	rows := ModuleImages(core, []script.UnownedRegion{region(0xffff800002000000, len(second), "module")}, kitNames)
	if len(rows) != 1 || !strings.Contains(rows[0], "source:/tmp/build/kit/hide.c") {
		t.Fatalf("the second segment's region should carry its own bytes: %v", rows)
	}
}

// A region larger than the per-region cap is not read, and the regions after it
// still are: one hostile allocation can neither silence the dig nor make it
// unbounded.
func TestModuleImagesRespectsTheRegionCap(t *testing.T) {
	huge := coreRegionCap + 1
	payload := []byte("/tmp/build/kit/hide.c\x00__this_module\x00")
	core := writeCore(t,
		coreSegment{vaddr: 0xffff800001000000, payload: make([]byte, huge)},
		coreSegment{vaddr: 0xffff800002000000, payload: payload},
	)
	regions := []script.UnownedRegion{
		region(0xffff800001000000, huge, "module"),
		region(0xffff800002000000, len(payload), "module"),
	}
	rows := ModuleImages(core, regions, kitNames)
	if len(rows) != 1 || !strings.Contains(rows[0], "0xffff800002000000") {
		t.Fatalf("only the region inside the cap should be read: %v", rows)
	}
}

// The dig is the local body's last step, and its rows belong with the memory they
// name: after every row nothing explains and before the accounting line that
// closes the report. The fixture's second unexplained region has no segment in
// this synthetic core, so it adds no row — the region that can be read does.
func TestModuleMemoryPlacesTheImageRowBeforeTheAccountingLine(t *testing.T) {
	views, _, _, _ := moduleMemoryFixture(t)
	// The core maps the whole region, as the kernel's own file does: the dig
	// reads a region through one segment, so a segment shorter than the region
	// is not the memory the row names.
	payload := make([]byte, 24576)
	copy(payload, "/home/lab/Diamorphine/diamorphine.c\x00diamorphine\x00__this_module\x00")
	views.CorePath = writeCore(t, coreSegment{vaddr: 0xffff8000017c5000, payload: payload})

	got, err := ModuleMemory(views, kitNames)(context.Background())
	if err != nil {
		t.Fatalf("the local body failed: %v", err)
	}
	want := []string{
		"UNOWNED 0xffff8000017c5000-0xffff8000017cb000 size 24576 caller module",
		"UNOWNED 0xffff800001900000-0xffff800001902000 size 28672 caller module diamorphine 2",
		"IMAGE 0xffff8000017c5000-0xffff8000017cb000 size 24576 ",
		"VMAP regions 3 modules 1 explained 1 unexplained 2",
	}
	rows := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(rows) != len(want) {
		t.Fatalf("the body rendered %d rows, want %d:\n%s", len(rows), len(want), got)
	}
	for index, prefix := range want {
		if !strings.HasPrefix(rows[index], prefix) {
			t.Errorf("row %d is %q, want it to start with %q", index, rows[index], prefix)
		}
	}
	if !strings.Contains(rows[2], "source:/home/lab/Diamorphine/diamorphine.c") {
		t.Errorf("the image row should carry what the bytes said: %q", rows[2])
	}
}

// A host whose core cannot be read answers exactly the rows the pipeline prints:
// the dig adds nothing, not a line about itself.
func TestModuleMemoryWithoutAReadableCoreIsThePipelineRows(t *testing.T) {
	views, _, _, _ := moduleMemoryFixture(t)
	got, err := ModuleMemory(views, kitNames)(context.Background())
	if err != nil {
		t.Fatalf("the local body failed: %v", err)
	}
	want := "UNOWNED 0xffff8000017c5000-0xffff8000017cb000 size 24576 caller module\n" +
		"UNOWNED 0xffff800001900000-0xffff800001902000 size 28672 caller module diamorphine 2\n" +
		"VMAP regions 3 modules 1 explained 1 unexplained 2\n"
	if got != want {
		t.Errorf("the body is\n%q\nwant\n%q", got, want)
	}
}
