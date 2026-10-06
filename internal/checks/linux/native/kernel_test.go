// The hidden-module diff reads three kernel surfaces. The parsing and the join
// are pure, so these tests feed bodies and fixture trees instead of the live
// kernel; the marked stream the body emits is what the shell block emits too, so
// the fixture rows here and in the linux package's pipeline test are the same
// shape.

package native

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/script"
)

// The tag is the last field, and the pseudo-module tags are not modules:
// counting them would make the diff report modules the kernel never loaded —
// [bpf] JITed programs, and the pages the kernel tags [__builtin__ftrace] and
// [__builtin__kprobes] for its ftrace and kprobes trampolines.
func TestSymbolModuleNamesCountsTagsAndSkipsPseudoModules(t *testing.T) {
	body := "ffffffff81000000 T startup_64\n" +
		"ffffffffc0567000 t nf_tables_init\t[nf_tables]\n" +
		"ffffffffc0567010 t nft_do_chain\t[nf_tables]\n" +
		"ffffffffc00a6c98 t bpf_prog_772db7720b2728e9_sd_fw_egress\t[bpf]\n" +
		"ffffffff82000000 t ftrace_trampoline\t[__builtin__ftrace]\n" +
		"ffffffff82000010 t ftrace_trampoline\t[__builtin__ftrace]\n" +
		"ffffffff82000020 t kprobe_trampoline\t[__builtin__kprobes]\n" +
		"ffffffffc05a4000 t my_sys_openat\t[rootkit]\n" +
		"ffffffffc05a4100 t fake_seq_show\t[rootkit]\n"
	want := map[string]int{"nf_tables": 2, "rootkit": 2}
	if got := symbolModuleNames(body); !maps.Equal(got, want) {
		t.Errorf("symbolModuleNames = %v, want %v", got, want)
	}
}

// hiddenModuleFixture writes the three views the diff reads: a rootkit sysfs and
// the symbol table carry while the module list does not, a ghost the list and the
// symbols carry while sysfs does not, an nf_tables all three carry, and a
// [bpf] pseudo-module tag that is not a module. It returns the sysfs root, the
// module list, and the symbol table.
func hiddenModuleFixture(t *testing.T) (sysfs, modules, symbols string) {
	t.Helper()
	root := t.TempDir()
	sysfs = filepath.Join(root, "sys", "module")
	module := filepath.Join(sysfs, "rootkit")
	if err := os.MkdirAll(filepath.Join(module, "sections"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(module, "coresize"), []byte("16384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(module, "taint"), []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(module, "sections", ".text"), []byte("0xffffffffc05a4000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysfs, "nf_tables", "sections"), 0o700); err != nil {
		t.Fatal(err)
	}
	modules = filepath.Join(root, "modules")
	list := "nf_tables 409600 0 - Live 0xffffffffc0567000\n" +
		"ghost 8192 0 - Live 0xffffffffc0580000\n"
	if err := os.WriteFile(modules, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	symbols = filepath.Join(root, "kallsyms")
	table := "ffffffff81000000 T startup_64\n" +
		"ffffffffc0567000 t nft_do_chain\t[nf_tables]\n" +
		"ffffffffc0580000 t ghost_init\t[ghost]\n" +
		"ffffffffc05a4000 t my_init\t[rootkit]\n" +
		"ffffffffc05a4010 t my_exit\t[rootkit]\n" +
		"ffffffffc0700000 t bpf_prog_1\t[bpf]\n"
	if err := os.WriteFile(symbols, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	return sysfs, modules, symbols
}

// fixtureViews is the fixture's view set: the real surfaces come from the check,
// the fixture substitutes its own paths.
func fixtureViews(sysfs, modules, symbols string) script.ModuleDiffViews {
	views := ModuleDiffViews([]ModuleAttr{{Label: "size", File: "coresize"}, {Label: "taint", File: "taint"}, {Label: "refs", File: "refcnt"}})
	views.SysfsRoot, views.ModulesPath, views.SymbolsPath = sysfs, modules, symbols
	return views
}

// The local channel's body is one tier: the three views are read in one call and
// the disagreements come out in one panel, with the attribute that reads back
// empty left off the line.
func TestModulesHiddenBodyReportsTheDisagreements(t *testing.T) {
	sysfs, modules, symbols := hiddenModuleFixture(t)
	got, err := ModulesHidden(fixtureViews(sysfs, modules, symbols))(context.Background())
	if err != nil {
		t.Fatalf("the body failed: %v", err)
	}
	want := "GAP ghost sysfs=no proc=yes kallsyms=yes symbols 1\n" +
		"HIDDEN rootkit sysfs=yes proc=no kallsyms=yes size 16384 symbols 2\n"
	if got != want {
		t.Errorf("the body printed\n%q\nwant\n%q", got, want)
	}
}

// A view that cannot be read is unknown rather than a verdict: with /sys
// unmounted the symbol table is the only view left, and every module the list
// names must not become a GAP row.
func TestModulesHiddenBodyMarksAnAbsentViewUnknown(t *testing.T) {
	_, modules, symbols := hiddenModuleFixture(t)
	views := fixtureViews(filepath.Join(t.TempDir(), "no-sys"), modules, symbols)
	got, err := ModulesHidden(views)(context.Background())
	if err != nil {
		t.Fatalf("the body failed: %v", err)
	}
	want := "HIDDEN rootkit sysfs=? proc=no kallsyms=yes symbols 2\n"
	if got != want {
		t.Errorf("the body printed %q, want %q", got, want)
	}
}

// Without the module list there is no baseline to diff against: every sysfs
// module and every symbol tag would read as hidden, so the tier reports itself
// unavailable and the chain is free to move on.
func TestModulesHiddenBodyRefusesWithoutTheModuleList(t *testing.T) {
	sysfs, _, symbols := hiddenModuleFixture(t)
	views := fixtureViews(sysfs, filepath.Join(t.TempDir(), "gone"), symbols)
	if _, err := ModulesHidden(views)(context.Background()); !errors.Is(err, model.ErrTierUnavailable) {
		t.Errorf("a missing module list should report the tier unavailable, got %v", err)
	}
}

// /proc/modules ends its dependent list with a comma; lsmod joins the holder
// names with commas and no terminator, so the trailing comma is dropped. The
// header is lsmod's own literal, which the generated one has to reproduce.
func TestLsmodRowsDropsTheTrailingComma(t *testing.T) {
	body := "inet_diag 24576 2 udp_diag,tcp_diag, Live 0x0000000000000000\n" +
		"kvm_intel 397312 0 - Live 0x0000000000000000\n" +
		"nf_tables 356352 3 nft_chain_filter, Live 0x0000000000000000 (E)\n"
	out := lsmodRows(body)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	wantHeader := "Module                  Size  Used by"
	if lines[0] != wantHeader {
		t.Errorf("header = %q, want lsmod's own %q", lines[0], wantHeader)
	}
	want := []string{
		fieldCell("inet_diag", "24576", "2") + " udp_diag,tcp_diag",
		fieldCell("kvm_intel", "397312", "0"),
		fieldCell("nf_tables", "356352", "3") + " nft_chain_filter",
	}
	for i, line := range lines[1:] {
		if line != want[i] {
			t.Errorf("row %d = %q, want %q", i, line, want[i])
		}
	}
	if strings.Contains(out, ",\n") {
		t.Errorf("a dependent list kept its terminator:\n%s", out)
	}
}

// fieldCell is lsmod's row prefix: name, size, use count — printf("%-19s %8ld  %d").
func fieldCell(name, size, count string) string {
	return fmt.Sprintf("%-19s %8s  %s", name, size, count)
}

// moduleMemoryFixture writes the three surfaces the module-memory diff reads: a
// module-only allocation the symbol table explains, one no symbol reaches (the
// memory a module leaves behind after removing its kobject and its list entry,
// which is what the check exists for), one carrying a symbol tagged with a
// module the list does not carry, and an allocation from an unrelated caller
// that is not executable module memory at all.
func moduleMemoryFixture(t *testing.T) (views script.ModuleMemoryViews, allocations, modules, symbols string) {
	t.Helper()
	root := t.TempDir()
	views = ModuleMemoryViews()
	allocations = filepath.Join(root, "vmallocinfo")
	body := "0xffff800001206000-0xffff80000120e000   32768 move_module+0x2c/0x1b4 pages=7 vmalloc N0=7\n" +
		"0xffff8000017c5000-0xffff8000017cb000   24576 move_module+0x2c/0x1b4 pages=5 vmalloc N0=5\n" +
		"0xffff800001900000-0xffff800001902000   28672 module_alloc+0x10/0x40 pages=6 vmalloc N0=6\n" +
		"0xffff000000000000-0xffff000000001000    4096 vmap\n"
	if err := os.WriteFile(allocations, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	modules = filepath.Join(root, "modules")
	list := "nf_tables 409600 0 - Live 0xffff800001206000\n"
	if err := os.WriteFile(modules, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	symbols = filepath.Join(root, "kallsyms")
	table := "ffff800001207000 t nft_do_chain\t[nf_tables]\n" +
		"ffff800001900000 t hidden_init\t[diamorphine]\n" +
		"ffff800001901000 t hidden_exit\t[diamorphine]\n"
	if err := os.WriteFile(symbols, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	views.VMallocPath, views.ModulesPath, views.SymbolsPath = allocations, modules, symbols
	return views, allocations, modules, symbols
}

// The local tier reads the three surfaces in process and joins them: an
// allocation with a listed module's symbol is explained, an anonymous one from
// the module loader's own allocator is reported, and one whose only symbols name
// an unlisted module is reported with that name — the two shapes a hidden module
// leaves. A caller that is not an allocator is not executable module memory.
func TestModuleMemoryBodyReportsUnexplainedRegions(t *testing.T) {
	views, _, _, _ := moduleMemoryFixture(t)
	got, err := ModuleMemory(views)(context.Background())
	if err != nil {
		t.Fatalf("the body failed: %v", err)
	}
	want := "UNOWNED 0xffff8000017c5000-0xffff8000017cb000 size 24576 caller module\n" +
		"UNOWNED 0xffff800001900000-0xffff800001902000 size 28672 caller module diamorphine 2\n" +
		"VMAP regions 3 modules 1 explained 1 unexplained 2\n"
	if got != want {
		t.Errorf("the body printed\n%q\nwant\n%q", got, want)
	}
}

// The marked stream is what the shell block emits too: one R line per
// allocation in file order (an unrelated caller is not a region at all), the
// module-list names, then a Y line per symbol inside an allocation, indexed by
// the allocation pass's own index and tagged the way kallsyms tags it.
func TestModuleMemoryTextCarriesTheRegionIndex(t *testing.T) {
	views, _, _, _ := moduleMemoryFixture(t)
	allocations, _ := os.ReadFile(views.VMallocPath)
	modules, _ := os.ReadFile(views.ModulesPath)
	symbols, _ := os.ReadFile(views.SymbolsPath)
	got := moduleMemoryText(views, string(allocations), string(modules), string(symbols))
	want := "R 1 0xffff800001206000 0xffff80000120e000 32768 module\n" +
		"R 2 0xffff8000017c5000 0xffff8000017cb000 24576 module\n" +
		"R 3 0xffff800001900000 0xffff800001902000 28672 module\n" +
		"P nf_tables\n" +
		"Y 1 nf_tables\n" +
		"Y 3 diamorphine\n" +
		"Y 3 diamorphine\n"
	if got != want {
		t.Errorf("the stream is\n%q\nwant\n%q", got, want)
	}
}
