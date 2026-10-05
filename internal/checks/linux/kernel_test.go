// The hidden-module cross-check's ssh branch is generated from the same
// attribute list the in-process branch reads, so the two channels cannot drift
// apart; this pins the generation to that single source.

package linux

import (
	"strings"
	"testing"
)

func TestHiddenModuleScriptCarriesEveryAttr(t *testing.T) {
	if len(hiddenModuleAttrs) == 0 {
		t.Fatal("the evidence line needs attributes")
	}
	for _, attr := range hiddenModuleAttrs {
		if pair := attr.Label + ":" + attr.File; !strings.Contains(hiddenModuleScript, pair) {
			t.Errorf("the script is missing %s", pair)
		}
	}
	if !strings.Contains(hiddenModuleScript, `grep -q "^$n " /proc/modules`) {
		t.Error("the script must diff /sys/module against the module list")
	}
}

// The kallsyms branch must exclude the [bpf] pseudo-module: its JITed programs
// are not modules, and reporting them would be a Critical false positive on any
// host running BPF.
func TestHiddenSymbolScriptExcludesBPF(t *testing.T) {
	if !strings.Contains(hiddenSymbolScript, `n != "[bpf]"`) {
		t.Error("the kallsyms diff must drop the [bpf] tag")
	}
	if !strings.Contains(hiddenSymbolScript, "/proc/modules /proc/kallsyms") {
		t.Error("the kallsyms diff reads both surfaces in one pass")
	}
}
