// The local channel's deeper read of the module-memory rows: the regions
// /proc/vmallocinfo names and neither the module list nor the symbol table can
// explain are read out of the running kernel's own core file, because the bytes
// still carry what the registries have lost.
//
// Two surfaces decide which regions to read, and both are the check's own: the
// allocation list says where a module's memory is (a page-table fact no userspace
// rootkit can unlink), and the kallsyms tags say which of those allocations a
// listed module reaches. What is left over belongs to something the registries do
// not name — and on a kernel where modules share execmem_alloc with JITed BPF
// programs and the kprobe and ftrace trampolines, "left over" alone is not a
// finding, so the bytes have to say what they are.
//
// What the bytes can say is bounded by what a module image carries. Its .strtab
// and its ksymtab strings travel with it (measured on the lab VM with Diamorphine
// loaded: `diamorphine`, `module_hide`, `hacked_getdents64`, `resolve_sym`,
// `__this_module`, `fh_hook [2]`), and so does the build-time source path the
// compiler baked in (`/home/lab/Diamorphine/diamorphine.c`). Its .modinfo is not:
// the loader discards that section, so `vermagic=` and `srcversion=` never appear
// in the memory and are not looked for here. Instruction bytes, which is what the
// anonymous JIT pages of a 6.10+ kernel are full of, are read as text by any
// printable-run scan (`SAUAVAW1` was the shape measured there) — which is why the
// dig requires a module-shaped signature and prints nothing without one.

package native

import (
	"cmp"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"karma/internal/script"
)

// The dig's bounds: a module image is tens of kilobytes (the hidden module on the
// lab is 24576 bytes), so these are far above any real one and exist only to keep
// a hostile host from making the read unbounded.
const (
	coreRegionCap = 4 << 20  // the largest region the dig reads
	coreScanCap   = 32 << 20 // the most it reads for one check
	// coreValuesCap is the most signatures one row carries, and it is what the
	// measured case needs: the hidden module on the lab answers with three names
	// from the catalog list (diamorphine, its cleanup symbol and the prefix it
	// hides files by), two source paths and the placeholder. A symbol-dense image
	// past this says how many it left out rather than turning one row into a
	// listing.
	coreValuesCap = 6
	coreRunMin    = 5 // the shortest printable run worth a pattern test
)

// The three shapes a module's naming evidence takes in its own memory, in the
// order the dig prefers them (see imageValue).
var (
	// imageFile names the module or library file: the .ko the loader was given,
	// or the .so a preload kit ships.
	imageFile = regexp.MustCompile(`\b[[:alnum:]_.+-]+\.(?:ko|so)\b`)
	// imageSource is a source path: the build tree __FILE__ baked in, or the
	// include path a WARN/BUG macro leaves behind. The leading slash is part of
	// the match — the build tree is what names the kit.
	imageSource = regexp.MustCompile(`/?(?:[[:alnum:]_.+-]+/)+[[:alnum:]_.+-]+\.(?:c|h)\b`)
	// imageMarker is the placeholder symbol every module carries and nothing
	// else in an executable allocation does.
	imageMarker = regexp.MustCompile(`\b__this_module\b`)
)

// How decisive one signature is, smallest first: a name the catalog knows beats
// a file name, which beats a path, which beats the placeholder.
const (
	rankKitName = iota
	rankFileName
	rankSource
	rankMarker
)

// ModuleImages reads the memory of the regions the module-memory cross-check
// could not explain and renders one row per region whose bytes carry a module's
// naming evidence. kitNames is the catalog's own rootkit name list (the check
// hands it in, as Kallsyms takes its pattern), matched with a separator
// continuation so a kit's own literals count (`diamorphine_secret`) while a word
// merely starting with a name does not (`reptilian`).
//
// Every way of not reading is the same answer — no rows: an empty or unreadable
// core (a kernel under lockdown, a container without one), a region the core does
// not map, a region with no signature in it. The UNOWNED row is the finding
// either way, and this is the extra evidence behind it, so a host that cannot be
// read adds nothing rather than a line about itself.
func ModuleImages(corePath string, unowned []script.UnownedRegion, kitNames *regexp.Regexp) []string {
	if corePath == "" || len(unowned) == 0 {
		return nil
	}
	core, err := os.Open(corePath)
	if err != nil {
		return nil
	}
	defer core.Close()
	loads, err := coreSegments(core)
	if err != nil {
		return nil
	}
	var (
		rows []string
		read int
	)
	for _, region := range unowned {
		if region.Start == 0 || region.Size <= 0 || region.Size > coreRegionCap || read+region.Size > coreScanCap {
			continue
		}
		segment, ok := segmentCovering(loads, region.Start, region.End)
		if !ok {
			continue
		}
		body := make([]byte, region.Size)
		got, err := core.ReadAt(body, int64(segment.Off+(region.Start-segment.Vaddr)))
		if got == 0 && err != nil {
			continue
		}
		read += got
		values := imageValues(body[:got], kitNames)
		if len(values) == 0 {
			continue
		}
		rows = append(rows, "IMAGE "+region.Range+" size "+strconv.Itoa(region.Size)+" "+strings.Join(values, " "))
	}
	return rows
}

// coreSegments is the core file's address map: its PT_LOAD segments, in
// ascending virtual address order. A region is read through the segment that
// covers it, at the segment's own file offset plus the distance from its start —
// the only mapping the kernel's core file offers.
func coreSegments(core io.ReaderAt) ([]*elf.Prog, error) {
	parsed, err := elf.NewFile(core)
	if err != nil {
		return nil, err
	}
	defer parsed.Close()
	var loads []*elf.Prog
	for _, prog := range parsed.Progs {
		if prog.Type == elf.PT_LOAD {
			loads = append(loads, prog)
		}
	}
	slices.SortFunc(loads, func(a, b *elf.Prog) int { return cmp.Compare(a.Vaddr, b.Vaddr) })
	return loads, nil
}

// segmentCovering finds the segment one region lies inside, if any: a region that
// crosses a segment boundary is not read, because the bytes on either side of it
// are not the same memory.
func segmentCovering(loads []*elf.Prog, start, end uint64) (*elf.Prog, bool) {
	for _, prog := range loads {
		if start >= prog.Vaddr && end <= prog.Vaddr+prog.Filesz {
			return prog, true
		}
	}
	return nil, false
}

// imageValues extracts the naming evidence from one region's bytes, most
// decisive first, deduplicated, at most coreValuesCap of them with a "+N" for the
// rest. A region with none returns nil.
func imageValues(data []byte, kitNames *regexp.Regexp) []string {
	seen := map[string]bool{}
	var values []imageValue
	add := func(rank int, kind, payload string) {
		token := kind + ":" + payload
		if seen[token] {
			return
		}
		seen[token] = true
		values = append(values, imageValue{rank: rank, token: token})
	}
	for _, run := range printableRuns(data, coreRunMin) {
		if kitNames != nil {
			for _, name := range kitNames.FindAllString(run, -1) {
				add(rankKitName, "name", name)
			}
		}
		for _, name := range imageFile.FindAllString(run, -1) {
			add(rankFileName, "file", name)
		}
		for _, path := range imageSource.FindAllString(run, -1) {
			add(rankSource, "source", path)
		}
		if imageMarker.MatchString(run) {
			add(rankMarker, "marker", "__this_module")
		}
	}
	if len(values) == 0 {
		return nil
	}
	slices.SortStableFunc(values, func(a, b imageValue) int {
		return cmp.Or(cmp.Compare(a.rank, b.rank), strings.Compare(a.token, b.token))
	})
	out := make([]string, 0, min(len(values), coreValuesCap)+1)
	for _, value := range values[:min(len(values), coreValuesCap)] {
		out = append(out, value.token)
	}
	if extra := len(values) - coreValuesCap; extra > 0 {
		out = append(out, fmt.Sprintf("+%d", extra))
	}
	return out
}

// imageValue is one signature with how decisive it is.
type imageValue struct {
	rank  int
	token string
}

// printableRuns returns the runs of printable ASCII at least min bytes long, in
// the order they appear. A run is cut at 256 bytes: a longer one is not a name,
// and the cut only bounds what the patterns are run over.
func printableRuns(data []byte, min int) []string {
	var (
		out []string
		run []byte
	)
	flush := func() {
		if len(run) >= min {
			out = append(out, string(run))
		}
		run = run[:0]
	}
	for _, char := range data {
		if char >= 0x20 && char < 0x7f {
			if len(run) < 256 {
				run = append(run, char)
			}
			continue
		}
		flush()
	}
	flush()
	return out
}
