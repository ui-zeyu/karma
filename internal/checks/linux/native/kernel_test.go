// The hidden-module cross-check is two kernel surfaces diffed against the module
// list. The parsing and the diff are pure, so these tests feed bodies instead of
// the live kernel; the attribute reader is exercised on a temporary directory.

package native

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
