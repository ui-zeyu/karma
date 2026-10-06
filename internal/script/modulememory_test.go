// The module-memory diff is one contract with two implementations: the Go join
// the local channel uses (ModuleMemoryBody) and the awk join the ssh and ttyd
// channels run (inside ModuleMemoryScript). These tests pin the rows, then run
// the awk over a marked stream built the way the shell builds it and compare the
// two line for line.

package script

import (
	"os/exec"
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

// runsMemoryAwkJoin runs the pipeline's join over a marked stream.
func runsMemoryAwkJoin(t *testing.T, stream string) string {
	t.Helper()
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("no awk on this host")
	}
	cmd := exec.Command("awk", "-v", "pseudo="+strings.Join(memoryViews().PseudoTags, " "), moduleMemoryAwk())
	cmd.Stdin = strings.NewReader(stream)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the join failed: %v (output %q)", err, out)
	}
	return string(out)
}

// compareJoins requires both implementations to render the same text.
func compareJoins(t *testing.T, stream string) string {
	t.Helper()
	want := ModuleMemoryBody(memoryViews(), stream)
	if got := runsMemoryAwkJoin(t, stream); got != want {
		t.Errorf("the awk join rendered\n%q\nwant\n%q", got, want)
	}
	return want
}

// A region the kernel's own module allocator made, with no symbols in it and no
// explanation anywhere, is the kobject_del case: the module is gone from
// /proc/modules and /sys/module both, and only its memory is left.
func TestModuleMemoryJoinReportsAnAnonymousModuleRegion(t *testing.T) {
	stream := "R 1 0xffff8000017c5000 0xffff8000017cb000 24576 module\n" +
		"P nf_tables\nP overlay\n"
	want := "UNOWNED 0xffff8000017c5000-0xffff8000017cb000 size 24576 caller module\n" +
		"VMAP regions 1 modules 2 explained 0 unexplained 1\n"
	if got := compareJoins(t, stream); got != want {
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
	if got := compareJoins(t, stream); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}

// A symbol tagged with a module the list does not carry is a hidden module's
// memory, whatever its allocator: the row names the module the tag names.
func TestModuleMemoryJoinReportsARegionTaggedWithAnUnlistedModule(t *testing.T) {
	stream := "R 1 0xffffffffc02a4000 0xffffffffc02a7000 12288 shared\n" +
		"P nf_tables\n" +
		"Y 1 diamorphine\nY 1 diamorphine\nY 1 nf_tables\n"
	want := "UNOWNED 0xffffffffc02a4000-0xffffffffc02a7000 size 12288 caller shared diamorphine 2 nf_tables 1\n" +
		"VMAP regions 1 modules 1 explained 0 unexplained 1\n"
	if got := compareJoins(t, stream); got != want {
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
		"Y 1 bpf\n" +
		"Y 2 -\n" +
		"Y 3 nft_do_chain\t[nf_tables]\n"
	// The tag in a Y line is the bare module name the shell awk writes.
	stream = strings.ReplaceAll(stream, "nft_do_chain\t[nf_tables]", "nf_tables")
	want := "VMAP regions 3 modules 1 explained 3 unexplained 0\n"
	if got := compareJoins(t, stream); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}

// The accounting line closes the report even when there is nothing to explain
// away, so a host's baseline is visible before anything changes.
func TestModuleMemoryJoinAlwaysAccounts(t *testing.T) {
	stream := "R 1 0xffff800001200000 0xffff800001206000 24576 module\n" +
		"R 2 0xffff800001206000 0xffff80000120e000 32768 module\n" +
		"P nf_tables\nP overlay\nP xfs\n" +
		"Y 1 nf_tables\nY 2 overlay\n"
	want := "VMAP regions 2 modules 3 explained 2 unexplained 0\n"
	if got := compareJoins(t, stream); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}
