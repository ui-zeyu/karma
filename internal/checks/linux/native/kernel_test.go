// The hidden-module cross-check is two kernel surfaces diffed against the module
// list. The parsing and the diff are pure, so these tests feed bodies instead of
// the live kernel; the attribute reader is exercised on a temporary directory.

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
)

func TestLoadedModuleNames(t *testing.T) {
	body := "nf_tables 409600 0 - Live 0xffffffffc0567000\n" +
		"nvidia 1234 5 - Live 0x0000000000000000 (POE)\n" +
		"\n"
	want := map[string]bool{"nf_tables": true, "nvidia": true}
	if got := loadedModuleNames(body); !maps.Equal(got, want) {
		t.Errorf("loadedModuleNames = %v, want %v", got, want)
	}
}

// The tag is the last field, and the [bpf] one is a JITed program, not a module:
// counting it would make the diff report a module the kernel never loaded.
func TestSymbolModuleNamesCountsTagsAndSkipsBPF(t *testing.T) {
	body := "ffffffff81000000 T startup_64\n" +
		"ffffffffc0567000 t nf_tables_init\t[nf_tables]\n" +
		"ffffffffc0567010 t nft_do_chain\t[nf_tables]\n" +
		"ffffffffc00a6c98 t bpf_prog_772db7720b2728e9_sd_fw_egress\t[bpf]\n" +
		"ffffffffc05a4000 t my_sys_openat\t[rootkit]\n" +
		"ffffffffc05a4100 t fake_seq_show\t[rootkit]\n"
	want := map[string]int{"nf_tables": 2, "rootkit": 2}
	if got := symbolModuleNames(body); !maps.Equal(got, want) {
		t.Errorf("symbolModuleNames = %v, want %v", got, want)
	}
}

func TestHiddenModuleSymbolLinesDiffsAndSorts(t *testing.T) {
	counts := map[string]int{"nf_tables": 245, "rootkit": 41, "aardvark": 1}
	loaded := map[string]bool{"nf_tables": true}
	want := "HIDDEN aardvark symbols 1\nHIDDEN rootkit symbols 41\n"
	if got := hiddenModuleSymbolLines(counts, loaded); got != want {
		t.Errorf("hiddenModuleSymbolLines = %q, want %q", got, want)
	}
}

// hiddenModuleFixture writes the two registries the cross-check diffs: a rootkit
// both of them carry and the module list does not, and an nf_tables the list
// carries. It returns the sysfs root, the module list, and the symbol table.
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
	if err := os.WriteFile(filepath.Join(module, "sections", ".text"), []byte("0xffffffffc05a4000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	modules = filepath.Join(root, "modules")
	if err := os.WriteFile(modules, []byte("nf_tables 409600 0 - Live 0xffffffffc0567000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symbols = filepath.Join(root, "kallsyms")
	table := "ffffffff81000000 T startup_64\n" +
		"ffffffffc0567000 t nft_do_chain\t[nf_tables]\n" +
		"ffffffffc05a4000 t my_init\t[rootkit]\n" +
		"ffffffffc05a4010 t my_exit\t[rootkit]\n" +
		"ffffffffc0700000 t bpf_prog_1\t[bpf]\n"
	if err := os.WriteFile(symbols, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	return sysfs, modules, symbols
}

// The merged body is one tier on the local channel too: both halves run in one
// call and both footprints come out in one panel.
func TestModulesHiddenBodyPrintsBothFootprints(t *testing.T) {
	sysfs, modules, symbols := hiddenModuleFixture(t)
	attrs := []ModuleAttr{{Label: "size", File: "coresize"}, {Label: "text", File: "sections/.text"}}
	got, err := hiddenModulesBody(attrs, sysfs, modules, symbols)(context.Background())
	if err != nil {
		t.Fatalf("the merged body failed: %v", err)
	}
	want := "HIDDEN rootkit size 16384 text 0xffffffffc05a4000\n" +
		"HIDDEN rootkit symbols 2\n"
	if got != want {
		t.Errorf("the merged body printed %q, want %q", got, want)
	}
}

// One surface missing takes its half out and leaves the other's evidence in
// place; only when both are gone is the tier unavailable and the chain free to
// move on.
func TestModulesHiddenBodyKeepsTheHalfThatAnswers(t *testing.T) {
	_, modules, symbols := hiddenModuleFixture(t)
	body := hiddenModulesBody(nil, filepath.Join(t.TempDir(), "no-sys"), modules, symbols)
	got, err := body(context.Background())
	if err != nil {
		t.Fatalf("the symbol half alone should answer: %v", err)
	}
	if want := "HIDDEN rootkit symbols 2\n"; got != want {
		t.Errorf("the symbol half printed %q, want %q", got, want)
	}

	both := hiddenModulesBody(nil, filepath.Join(t.TempDir(), "no-sys"),
		filepath.Join(t.TempDir(), "gone"), filepath.Join(t.TempDir(), "gone"))
	if _, err := both(context.Background()); !errors.Is(err, model.ErrTierUnavailable) {
		t.Errorf("both halves gone should report the tier unavailable, got %v", err)
	}
}

// An attribute that is missing or reads back empty (a module without taint
// letters) drops out of the line rather than printing a blank field.
func TestHiddenModuleLineSkipsEmptyAttrs(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sections"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"coresize":       "16384\n",
		"taint":          "\n",
		"sections/.text": "0xffffffffc05a4000\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	attrs := []ModuleAttr{
		{Label: "size", File: "coresize"},
		{Label: "init", File: "initsize"},
		{Label: "taint", File: "taint"},
		{Label: "text", File: "sections/.text"},
	}
	read := func(file string) (string, bool) { return readTrimmedFile(filepath.Join(dir, file)) }
	want := "HIDDEN rootkit size 16384 text 0xffffffffc05a4000"
	if got := hiddenModuleLine("rootkit", attrs, read); got != want {
		t.Errorf("hiddenModuleLine = %q, want %q", got, want)
	}
	if strings.Count(hiddenModuleLine("pathless", attrs, read), "HIDDEN ") != 1 {
		t.Error("a module with no readable attribute still needs its marker line")
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
