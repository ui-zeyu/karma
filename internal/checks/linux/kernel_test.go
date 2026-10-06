// The hidden-module diff ships one shell pipeline (three views, one script),
// and its text is a contract with awk and sort rather than with Go: these tests
// run the same pipeline the ssh channel runs, against a fixture registry, so a
// broken pipeline fails here instead of silently reporting nothing on a target.

package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"karma/internal/checks/linux/native"
	"karma/internal/script"
)

// requireSh skips a pipeline test on a host without the tools the pipeline is
// written in.
func requireSh(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s on this host", tool)
		}
	}
}

func runPipeline(t *testing.T, script string) string {
	t.Helper()
	out, err := exec.Command("/bin/sh", "-c", script).Output()
	if err != nil {
		t.Fatalf("the pipeline failed: %v (output %q)", err, out)
	}
	return string(out)
}

func writeAttr(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// hiddenModuleFixture is the three views the diff reads, on disk: a rootkit both
// sysfs and the symbol table carry and the module list does not, a ghost the list
// and the symbols carry but sysfs does not, an nf_tables all three carry, a
// built-in module with no sections/ directory (so not a candidate), and the two
// pseudo-module tags — a [bpf] JITed program and the kernel's own ftrace
// trampolines — that are not modules and must not read as hidden ones.
func hiddenModuleFixture(t *testing.T) (sysfs, modules, symbols string) {
	t.Helper()
	root := t.TempDir()
	sysfs = filepath.Join(root, "sys", "module")
	module := filepath.Join(sysfs, "rootkit")
	writeAttr(t, filepath.Join(module, "coresize"), "16384")
	writeAttr(t, filepath.Join(module, "initsize"), "8192")
	writeAttr(t, filepath.Join(module, "refcnt"), "0")
	writeAttr(t, filepath.Join(module, "initstate"), "live")
	writeAttr(t, filepath.Join(module, "taint"), "O")
	writeAttr(t, filepath.Join(module, "sections", ".text"), "0xffffffffc05a4000")
	if err := os.MkdirAll(filepath.Join(sysfs, "builtin"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeAttr(t, filepath.Join(sysfs, "nf_tables", "sections", ".text"), "0xffffffffc0567000")
	modules = filepath.Join(root, "modules")
	body := "nf_tables 409600 0 - Live 0xffffffffc0567000\n" +
		"ghost 8192 0 - Live 0xffffffffc0580000\n"
	if err := os.WriteFile(modules, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	symbols = filepath.Join(root, "kallsyms")
	kallsyms := strings.Join([]string{
		"ffffffff81000000 T startup_64",
		"ffffffffc0567000 t nft_do_chain\t[nf_tables]",
		"ffffffffc0580000 t ghost_init\t[ghost]",
		"ffffffffc05a4000 t my_init\t[rootkit]",
		"ffffffffc05a4010 t my_exit\t[rootkit]",
		"ffffffffc0700000 t bpf_prog_1\t[bpf]",
		"ffffffff82000000 t ftrace_trampoline\t[__builtin__ftrace]",
		"ffffffff82000010 t ftrace_trampoline\t[__builtin__ftrace]",
		"ffffffff82000020 t kprobe_trampoline\t[__builtin__kprobes]",
		"",
	}, "\n")
	if err := os.WriteFile(symbols, []byte(kallsyms), 0o644); err != nil {
		t.Fatal(err)
	}
	return sysfs, modules, symbols
}

// fixtureViews is the fixture's view set: the real surfaces come from the check,
// the fixture substitutes its own paths.
func fixtureViews(sysfs, modules, symbols string) script.ModuleDiffViews {
	views := hiddenModuleViews
	views.SysfsRoot, views.ModulesPath, views.SymbolsPath = sysfs, modules, symbols
	return views
}

// The pipeline reports the two directions the three views can disagree in, one
// row per name with all three verdicts: a module the list has forgotten while
// sysfs and the symbol table still carry it (HIDDEN), and one the list carries
// while sysfs has no kobject for it (GAP). A module all three views agree on, a
// built-in without a sections/ directory, and the pseudo-module tags stay quiet.
func TestHiddenModulePipelineReportsEveryDisagreement(t *testing.T) {
	requireSh(t, "sh", "awk", "sort")
	sysfs, modules, symbols := hiddenModuleFixture(t)
	got := runPipeline(t, script.HiddenModuleScript(fixtureViews(sysfs, modules, symbols)))
	want := "GAP ghost sysfs=no proc=yes kallsyms=yes symbols 1\n" +
		"HIDDEN rootkit sysfs=yes proc=no kallsyms=yes size 16384 init 8192 refs 0 state live taint O symbols 2\n"
	if got != want {
		t.Errorf("the diff printed:\n%q\nwant:\n%q", got, want)
	}
}

// A name only the symbol table is missing is not a finding: a kernel built
// without CONFIG_KALLSYMS_ALL tags few of its modules, and reporting those would
// bury the rows that matter. nf_tables is the case here — sysfs and the module
// list both carry it, the table tags none of its symbols.
func TestHiddenModulePipelineIsQuietAboutAMissingSymbolTag(t *testing.T) {
	requireSh(t, "sh", "awk", "sort")
	sysfs, modules, symbols := hiddenModuleFixture(t)
	if err := os.WriteFile(modules, []byte("nf_tables 409600 0 - Live 0xffffffffc0567000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := "ffffffffc05a4000 t my_init\t[rootkit]\n" +
		"ffffffffc05a4010 t my_exit\t[rootkit]\n" +
		"ffffffff82000000 t ftrace_trampoline\t[__builtin__ftrace]\n"
	if err := os.WriteFile(symbols, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := runPipeline(t, script.HiddenModuleScript(fixtureViews(sysfs, modules, symbols)))
	want := "HIDDEN rootkit sysfs=yes proc=no kallsyms=yes size 16384 init 8192 refs 0 state live taint O symbols 2\n"
	if got != want {
		t.Errorf("the diff printed %q, want %q", got, want)
	}
}

// An unreadable module list is an unavailable tier, not a registry with nothing
// in it: every sysfs module and every symbol tag would read as hidden otherwise.
func TestHiddenModulePipelineRefusesWithoutTheModuleList(t *testing.T) {
	requireSh(t, "sh", "awk", "sort")
	sysfs, _, symbols := hiddenModuleFixture(t)
	views := fixtureViews(sysfs, filepath.Join(t.TempDir(), "absent"), symbols)
	out, err := exec.Command("/bin/sh", "-c", script.HiddenModuleScript(views)).Output()
	if err == nil {
		t.Fatalf("the diff answered %q without a module list", out)
	}
	if len(out) != 0 {
		t.Errorf("the diff printed %q without a module list", out)
	}
}

// The two views that can be missing report themselves as unknown rather than as
// a verdict: a container without /sys mounted must not turn every module into a
// GAP row.
func TestHiddenModulePipelineMarksAnAbsentViewUnknown(t *testing.T) {
	requireSh(t, "sh", "awk", "sort")
	_, modules, symbols := hiddenModuleFixture(t)
	views := fixtureViews(filepath.Join(t.TempDir(), "absent"), modules, symbols)
	got := runPipeline(t, script.HiddenModuleScript(views))
	want := "HIDDEN rootkit sysfs=? proc=no kallsyms=yes symbols 2\n"
	if got != want {
		t.Errorf("the diff printed %q, want %q", got, want)
	}
}

// The module-memory pipeline is the ssh channel's half of the same rows the
// local tier renders in process. Its awk compares the allocation ranges as
// fixed-width hex strings and joins three files in one pass, so both the range
// test and the attribution are exercised over a fixture that has the two shapes
// a hidden module leaves: memory no symbol reaches, and memory whose only symbol
// names a module the list does not carry.
func TestModuleMemoryPipelineMatchesTheLocalBody(t *testing.T) {
	requireSh(t, "sh", "awk")
	root := t.TempDir()
	views := native.ModuleMemoryViews()
	allocations := filepath.Join(root, "vmallocinfo")
	body := "0xffff800001206000-0xffff80000120e000   32768 move_module+0x2c/0x1b4 pages=7 vmalloc N0=7\n" +
		"0xffff8000017c5000-0xffff8000017cb000   24576 move_module+0x2c/0x1b4 pages=5 vmalloc N0=5\n" +
		"0xffff800001900000-0xffff800001902000   28672 module_alloc+0x10/0x40 pages=6 vmalloc N0=6\n" +
		"0xffffffffc009b000-0xffffffffc029c000 2101248 execmem_alloc+0x97/0x1d0 pages=512 vmalloc N0=512\n" +
		"0xffff000000000000-0xffff000000001000    4096 vmap\n"
	if err := os.WriteFile(allocations, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	modules := filepath.Join(root, "modules")
	list := "nf_tables 409600 0 - Live 0xffff800001206000\n"
	if err := os.WriteFile(modules, []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}
	symbols := filepath.Join(root, "kallsyms")
	table := "ffff800001207000 t nft_do_chain\t[nf_tables]\n" +
		"ffff800001900000 t hidden_init\t[diamorphine]\n" +
		"ffff800001901000 t hidden_exit\t[diamorphine]\n" +
		"ffffffffc00a6c98 t bpf_prog_772db7720b2728e9\t[bpf]\n"
	if err := os.WriteFile(symbols, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	views.VMallocPath, views.ModulesPath, views.SymbolsPath = allocations, modules, symbols
	// The dig behind the local body reads the core file: point it at nothing, so
	// this test compares the two joins and never this host's own kernel memory.
	views.CorePath = filepath.Join(root, "no-core")

	got := runPipeline(t, script.ModuleMemoryScript(views))
	want, err := native.ModuleMemory(views, moduleImagesRe)(context.Background())
	if err != nil {
		t.Fatalf("the local body failed: %v", err)
	}
	if got != want {
		t.Errorf("the pipeline rendered\n%q\nwant\n%q", got, want)
	}
	if !strings.Contains(want, "UNOWNED 0xffff8000017c5000-0xffff8000017cb000 size 24576 caller module\n") {
		t.Errorf("the anonymous module allocation is missing from\n%q", want)
	}
	if !strings.Contains(want, "UNOWNED 0xffff800001900000-0xffff800001902000 size 28672 caller module diamorphine 2\n") {
		t.Errorf("the symbol-tagged allocation is missing from\n%q", want)
	}
	if !strings.Contains(want, "VMAP regions 4 modules 1 explained 2 unexplained 2\n") {
		t.Errorf("the accounting line is wrong in\n%q", want)
	}
}

// An allocation from the shared allocator with only a pseudo-module tag is the
// kernel's own JIT or trampoline memory: counted as unexplained, never a
// finding, which is what keeps the check quiet on a stock 6.10+ kernel.
func TestModuleMemoryPipelineIsQuietAboutKernelJitMemory(t *testing.T) {
	requireSh(t, "sh", "awk")
	root := t.TempDir()
	views := native.ModuleMemoryViews()
	allocations := filepath.Join(root, "vmallocinfo")
	body := "0xffffffffc009b000-0xffffffffc029c000 2101248 execmem_alloc+0x97/0x1d0 pages=512 vmalloc N0=512\n"
	if err := os.WriteFile(allocations, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	modules := filepath.Join(root, "modules")
	if err := os.WriteFile(modules, []byte("nf_tables 409600 0 - Live 0xffff800001206000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	symbols := filepath.Join(root, "kallsyms")
	table := "ffffffffc00a6c98 t bpf_prog_772db7720b2728e9\t[bpf]\n"
	if err := os.WriteFile(symbols, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	views.VMallocPath, views.ModulesPath, views.SymbolsPath = allocations, modules, symbols
	views.CorePath = filepath.Join(root, "no-core")
	got := runPipeline(t, script.ModuleMemoryScript(views))
	if want := "VMAP regions 1 modules 1 explained 1 unexplained 0\n"; got != want {
		t.Errorf("the pipeline rendered %q, want %q", got, want)
	}
}
