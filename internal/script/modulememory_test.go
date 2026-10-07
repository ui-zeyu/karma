// ModuleMemoryBody is the one join of the module-memory diff: both sources emit
// the marked record stream (the target's shell block and the in-process emitter)
// and the check hangs this function on the tier as its Assemble. These tests pin
// the rows over built streams; the emitters themselves are compared in the linux
// catalog's test, over one fixture.

package script

import (
	"slices"
	"strings"
	"testing"
)

// memoryViews is the view set the join needs: the pseudo-module tags are the one
// piece of configuration it reads, and the surfaces are unused by a join over an
// already-marked stream.
func memoryViews() ModuleMemoryViews {
	return ModuleMemoryViews{
		VMallocPath:      "/proc/vmallocinfo",
		ModulesPath:      "/proc/modules",
		SymbolsPath:      "/proc/kallsyms",
		ModuleAllocators: []string{"move_module", "module_alloc"},
		SharedAllocators: []string{"execmem_alloc"},
		PseudoTags:       []string{"bpf", "__builtin__ftrace", "__builtin__kprobes"},
	}
}

// joined renders one built stream, the way the tier's Assemble does.
func joined(stream string) string {
	return ModuleMemoryBody(memoryViews(), stream)
}

// A region the kernel's own module allocator made, with no symbols in it and no
// explanation anywhere, is the kobject_del case: the module is gone from
// /proc/modules and /sys/module both, and only its memory is left.
func TestModuleMemoryJoinReportsAnAnonymousModuleRegion(t *testing.T) {
	stream := "R 1 0xffff8000017c5000 0xffff8000017cb000 24576 module\n" +
		"P nf_tables\nP overlay\n"
	want := "UNOWNED 0xffff8000017c5000-0xffff8000017cb000 size 24576 caller module\n" +
		"VMAP regions 1 modules 2 explained 0 unexplained 1\n"
	if got := joined(stream); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}

// A shared allocator's anonymous region is the kernel's own business — JITed BPF
// programs, kprobe and ftrace trampolines all come from execmem_alloc on 6.10
// and later — so it counts as unexplained without being a finding.
func TestModuleMemoryJoinIsQuietAboutASharedAnonymousRegion(t *testing.T) {
	stream := "R 1 0xffffffffc0366000 0xffffffffc0368000 8192 shared\n" +
		"P nf_tables\n"
	want := "VMAP regions 1 modules 1 explained 0 unexplained 1\n"
	if got := joined(stream); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}

// A symbol tagged with a module the list does not carry is a hidden module's
// memory, whatever its allocator: the row names the module the tag names.
func TestModuleMemoryJoinReportsARegionTaggedWithAnUnlistedModule(t *testing.T) {
	stream := "R 1 0xffffffffc02a4000 0xffffffffc02a7000 12288 shared\n" +
		"P nf_tables\n" +
		"Y 1 diamorphine 2\nY 1 nf_tables 1\n"
	want := "UNOWNED 0xffffffffc02a4000-0xffffffffc02a7000 size 12288 caller shared diamorphine 2 nf_tables 1\n" +
		"VMAP regions 1 modules 1 explained 0 unexplained 1\n"
	if got := joined(stream); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}

// A region whose every symbol names a listed module, a pseudo-module or the
// kernel itself is explained, and the accounting line is the only output.
func TestModuleMemoryJoinExplainsRegionsByTheirSymbols(t *testing.T) {
	stream := "R 1 0xffffffffc009b000 0xffffffffc029c000 2101248 shared\n" +
		"R 2 0xffffffffc0625000 0xffffffffc0627000 8192 shared\n" +
		"R 3 0xffff800001200000 0xffff800001206000 24576 module\n" +
		"P nf_tables\n" +
		"Y 1 bpf 1\n" +
		"Y 2 - 1\n" +
		"Y 3 nf_tables 1\n"
	want := "VMAP regions 3 modules 1 explained 3 unexplained 0\n"
	if got := joined(stream); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}

// A region holding both a published kernel address and a symbol of a module the
// registry does not carry names both in one label list, in the order the symbol
// stream brought them: the two joins agree on the count of the untagged symbol
// ("-") as well, which is what the label list is read for.
func TestModuleMemoryJoinCountsTheUntaggedSymbolInTheLabelList(t *testing.T) {
	streams := []string{
		"R 1 0xffffffffc02a4000 0xffffffffc02a7000 12288 shared\n" +
			"P nf_tables\n" +
			"Y 1 - 1\nY 1 diamorphine 1\n",
		"R 1 0xffffffffc02a4000 0xffffffffc02a7000 12288 shared\n" +
			"P nf_tables\n" +
			"Y 1 diamorphine 1\nY 1 - 2\n",
	}
	wants := []string{
		"UNOWNED 0xffffffffc02a4000-0xffffffffc02a7000 size 12288 caller shared - 1 diamorphine 1\n" +
			"VMAP regions 1 modules 1 explained 0 unexplained 1\n",
		"UNOWNED 0xffffffffc02a4000-0xffffffffc02a7000 size 12288 caller shared diamorphine 1 - 2\n" +
			"VMAP regions 1 modules 1 explained 0 unexplained 1\n",
	}
	for index, stream := range streams {
		if got := joined(stream); got != wants[index] {
			t.Errorf("the join rendered\n%q\nwant\n%q", got, wants[index])
		}
	}
}

// The accounting line closes the report even when there is nothing to explain
// away, so a host's baseline is visible before anything changes.
func TestModuleMemoryJoinAlwaysAccounts(t *testing.T) {
	stream := "R 1 0xffff800001200000 0xffff800001206000 24576 module\n" +
		"R 2 0xffff800001206000 0xffff80000120e000 32768 module\n" +
		"P nf_tables\nP overlay\nP xfs\n" +
		"Y 1 nf_tables 1\nY 2 overlay 1\n"
	want := "VMAP regions 2 modules 3 explained 2 unexplained 0\n"
	if got := joined(stream); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}

// The rows come back with the regions they name, so a caller that wants to read
// the memory behind them (the local channel's core dig) takes the addresses
// instead of parsing the row back. The two have to name the same bytes: the
// spelling stays the one /proc/vmallocinfo wrote, and the numbers are the same
// range.
func TestModuleMemoryRowsReturnsTheRegionsItsRowsName(t *testing.T) {
	stream := "R 1 0xffff8000017c5000 0xffff8000017cb000 24576 module\n" +
		"R 2 0xffffffffc02a4000 0xffffffffc02a7000 12288 shared\n" +
		"R 3 0xffff800001200000 0xffff800001206000 24576 module\n" +
		"P nf_tables\n" +
		"Y 2 diamorphine 1\n" +
		"Y 3 nf_tables 1\n"
	rows, unowned := ModuleMemoryRows(memoryViews(), stream)
	want := []string{
		"UNOWNED 0xffff8000017c5000-0xffff8000017cb000 size 24576 caller module",
		"UNOWNED 0xffffffffc02a4000-0xffffffffc02a7000 size 12288 caller shared diamorphine 1",
		"VMAP regions 3 modules 1 explained 1 unexplained 2",
	}
	if !slices.Equal(rows, want) {
		t.Fatalf("the join rendered\n%q\nwant\n%q", rows, want)
	}
	if len(unowned) != 2 {
		t.Fatalf("the join returned %d regions, want the 2 its rows name: %+v", len(unowned), unowned)
	}
	if first := unowned[0]; first != (UnownedRegion{
		Range: "0xffff8000017c5000-0xffff8000017cb000",
		Start: 0xffff8000017c5000, End: 0xffff8000017cb000, Size: 24576, Caller: "module",
	}) {
		t.Errorf("the anonymous module region came back as %+v", first)
	}
	if second := unowned[1]; second.Range != "0xffffffffc02a4000-0xffffffffc02a7000" ||
		second.Start != 0xffffffffc02a4000 || second.Caller != "shared" {
		t.Errorf("the tagged region came back as %+v", second)
	}
	for index, region := range unowned {
		if !strings.HasPrefix(rows[index], "UNOWNED "+region.Range+" size ") {
			t.Errorf("row %d and region %d name different bytes: %q vs %+v", index, index, rows[index], region)
		}
	}
}

// A range the kernel would not write leaves the addresses zero, which no memory
// is mapped at, so the dig reads nothing rather than the wrong bytes.
func TestModuleMemoryRowsLeavesAMalformedRangeUnreadable(t *testing.T) {
	rows, unowned := ModuleMemoryRows(memoryViews(), "R 1 junk junk 4096 module\nP nf_tables\n")
	if len(unowned) != 1 || unowned[0].Start != 0 || unowned[0].End != 0 || unowned[0].Size != 4096 {
		t.Fatalf("a malformed range came back as %+v (rows %q)", unowned, rows)
	}
}
