// HiddenModuleBody is the one join of the hidden-module diff: both sources emit
// the marked record stream (the target's shell block and the in-process emitter)
// and the check hangs this function on the tier as its Assemble. These tests pin
// the row shape and the verdicts over built streams; the emitters themselves are
// compared in the linux catalog's test, over one fixture tree.

package script

import (
	"strings"
	"testing"
)

// markedModuleStream builds the stream HiddenModuleScript's shell block emits:
// the two availability flags, then one S line per sysfs module, one P line per
// module-list name, one K line per symbol-table tag. An unavailable view emits
// no lines of its own — that is what makes its verdict unknown rather than no.
func markedModuleStream(sysfsAvailable, symbolsAvailable bool) string {
	var b strings.Builder
	flag := func(ok bool) string {
		if ok {
			return "1"
		}
		return "0"
	}
	b.WriteString("A sysfs " + flag(sysfsAvailable) + "\n")
	b.WriteString("A kallsyms " + flag(symbolsAvailable) + "\n")
	if sysfsAvailable {
		b.WriteString("S nf_tables size 409600 refs 3 state live taint OE\n")
		b.WriteString("S rootkit size 16384 refs 0 state live taint O\n")
	}
	b.WriteString("P nf_tables\n")
	b.WriteString("P ghost\n")
	if symbolsAvailable {
		b.WriteString("K nf_tables 412\n")
		b.WriteString("K rootkit 2\n")
		b.WriteString("K ghost 1\n")
	}
	return b.String()
}

// Every disagreement gets one row with all three verdicts, and the views that
// agree print nothing: nf_tables is in all three, ghost is in the list and the
// symbol table while the sysfs registry has no kobject for it, and rootkit is in
// sysfs and the symbol table while the list has forgotten it.
func TestHiddenModuleJoinReportsEveryDisagreement(t *testing.T) {
	want := "GAP ghost sysfs=no proc=yes kallsyms=yes symbols 1\n" +
		"HIDDEN rootkit sysfs=yes proc=no kallsyms=yes size 16384 refs 0 state live taint O symbols 2\n"
	if got := HiddenModuleBody(markedModuleStream(true, true)); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}

// A view that could not be read is unknown, not a verdict: with /sys unmounted
// every module the list names must not become a GAP row, and the sysfs verdict
// reads "?". The symbols only row is what is left, without attributes — they
// come from sysfs, which is the view that is missing.
func TestHiddenModuleJoinMarksAnAbsentViewUnknown(t *testing.T) {
	want := "HIDDEN rootkit sysfs=? proc=no kallsyms=yes symbols 2\n"
	if got := HiddenModuleBody(markedModuleStream(false, true)); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}

// A name only the symbol table is missing stays out of the report: a kernel
// built without CONFIG_KALLSYMS_ALL tags few of its modules, and those rows
// would bury the ones that matter.
func TestHiddenModuleJoinIsQuietAboutAMissingSymbolTag(t *testing.T) {
	stream := "A sysfs 1\nA kallsyms 1\n" +
		"S nf_tables size 409600\nP nf_tables\n"
	if got := HiddenModuleBody(stream); got != "" {
		t.Errorf("the join rendered %q, want nothing", got)
	}
}

// A module the symbol table alone carries is the shape a rootkit that also
// dropped its kobject leaves: the row names the view that still has it.
func TestHiddenModuleJoinReportsASymbolOnlyModule(t *testing.T) {
	stream := "A sysfs 1\nA kallsyms 1\nK hidden 3\n"
	want := "HIDDEN hidden sysfs=no proc=no kallsyms=yes symbols 3\n"
	if got := HiddenModuleBody(stream); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}

// A module with no attributes that read back gets no empty tail: the row ends
// after the verdicts.
func TestHiddenModuleJoinPrintsNoEmptyAttributeTail(t *testing.T) {
	stream := "A sysfs 1\nA kallsyms 1\nS rootkit\nK rootkit 2\n"
	want := "HIDDEN rootkit sysfs=yes proc=no kallsyms=yes symbols 2\n"
	if got := HiddenModuleBody(stream); got != want {
		t.Errorf("the join rendered\n%q\nwant\n%q", got, want)
	}
}
