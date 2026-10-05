// The hidden-module cross-check ships one shell pipeline (both halves in one
// script), and its text is a contract with awk, grep and sort rather than with
// Go: these tests run the same pipelines the ssh channel runs, against a fixture
// registry, so a broken pipeline fails here instead of silently reporting
// nothing on a target.

package linux

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

// hiddenModuleFixture is the two registries the cross-check diffs, on disk: a
// rootkit both of them carry and the module list does not, an nf_tables the list
// carries, a built-in module with no sections/ directory (so not a candidate),
// and a [bpf] tag that is a JITed program rather than a module.
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
	if err := os.WriteFile(modules, []byte("nf_tables 409600 0 - Live 0xffffffffc0567000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	symbols = filepath.Join(root, "kallsyms")
	kallsyms := strings.Join([]string{
		"ffffffff81000000 T startup_64",
		"ffffffffc0567000 t nft_do_chain\t[nf_tables]",
		"ffffffffc05a4000 t my_init\t[rootkit]",
		"ffffffffc05a4010 t my_exit\t[rootkit]",
		"ffffffffc0700000 t bpf_prog_1\t[bpf]",
		"",
	}, "\n")
	if err := os.WriteFile(symbols, []byte(kallsyms), 0o644); err != nil {
		t.Fatal(err)
	}
	return sysfs, modules, symbols
}

// The sysfs diff walks the module directories of one root and prints the ones
// the module list does not carry, with the attributes the check handed in: a
// built-in module has no sections/ directory and is not a candidate, and a
// loadable module the list names is not hidden.
func TestHiddenSysfsDiffFindsAHiddenModule(t *testing.T) {
	requireSh(t, "sh", "grep")
	sysfs, modules, _ := hiddenModuleFixture(t)
	got := runPipeline(t, hiddenSysfsDiffText(hiddenModuleAttrs, sysfs, modules))
	want := "HIDDEN rootkit size 16384 init 8192 refs 0 state live taint O text 0xffffffffc05a4000\n"
	if got != want {
		t.Errorf("the sysfs diff printed %q, want %q", got, want)
	}
}

// The kallsyms diff reads two files in one awk pass: the module list decides
// what is expected, the symbol tags are the second registry. The [bpf]
// pseudo-module and the modules the list carries stay out.
func TestHiddenSymbolDiffFindsAHiddenModule(t *testing.T) {
	requireSh(t, "sh", "awk", "sort", "uniq")
	_, modules, symbols := hiddenModuleFixture(t)
	got := runPipeline(t, hiddenSymbolDiffText(modules, symbols))
	want := "HIDDEN rootkit symbols 2\n"
	if got != want {
		t.Errorf("the kallsyms diff printed %q, want %q", got, want)
	}
}

// An empty module list is a registry with nothing in it, and the symbol half has
// to read the table from its first line: the NR==FNR idiom would take that line
// for the module list instead and drop whatever tag it carries.
func TestHiddenSymbolDiffReadsTheTableFromItsFirstLine(t *testing.T) {
	requireSh(t, "sh", "awk", "sort", "uniq")
	root := t.TempDir()
	modules := filepath.Join(root, "modules")
	if err := os.WriteFile(modules, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	symbols := filepath.Join(root, "kallsyms")
	body := "ffffffffc05a4000 t my_init\t[rootkit]\n" +
		"ffffffffc05a4010 t my_exit\t[rootkit]\n"
	if err := os.WriteFile(symbols, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := runPipeline(t, hiddenSymbolDiffText(modules, symbols))
	want := "HIDDEN rootkit symbols 2\n"
	if got != want {
		t.Errorf("the kallsyms diff printed %q, want %q", got, want)
	}
}

// The tier runs both halves in one script, so one run carries both footprints in
// one panel. A half that ends the script — the sysfs half used to close with
// `exit 0` — makes the tier answer with that half alone, which is exactly what
// this test holds off.
func TestHiddenModuleScriptPrintsBothFootprints(t *testing.T) {
	requireSh(t, "sh", "awk", "sort", "uniq", "grep")
	sysfs, modules, symbols := hiddenModuleFixture(t)
	got := runPipeline(t, hiddenModuleDiffText(hiddenModuleAttrs, sysfs, modules, symbols))
	want := "HIDDEN rootkit size 16384 init 8192 refs 0 state live taint O text 0xffffffffc05a4000\n" +
		"HIDDEN rootkit symbols 2\n"
	if got != want {
		t.Errorf("the merged script printed %q, want %q", got, want)
	}
}
