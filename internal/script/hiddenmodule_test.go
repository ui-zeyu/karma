// The hidden-module diff is one contract with two implementations: the Go join
// the local channel uses (HiddenModuleBody) and the awk join the ssh and ttyd
// channels run (inside HiddenModuleScript). These tests pin the row shape, then
// run the awk over a marked stream built the way the shell builds it and compare
// the two line for line, so a verdict, an availability marker or an attribute
// change cannot land on one side alone.

package script

import (
	"os/exec"
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

// runsAwkJoin runs the pipeline's awk program over a marked stream and returns
// the rows, sorted the way the pipeline sorts them.
func runsAwkJoin(t *testing.T, stream string) string {
	t.Helper()
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("no awk on this host")
	}
	join := exec.Command("awk", hiddenModuleAwk())
	join.Stdin = strings.NewReader(stream)
	rows, err := join.Output()
	if err != nil {
		t.Fatalf("the join failed: %v (output %q)", err, rows)
	}
	if _, err := exec.LookPath("sort"); err != nil {
		t.Skip("no sort on this host")
	}
	sorter := exec.Command("sort", "-k2,2")
	sorter.Env = append(sorter.Environ(), "LC_ALL=C")
	sorter.Stdin = strings.NewReader(string(rows))
	sorted, err := sorter.Output()
	if err != nil {
		t.Fatalf("the sort failed: %v (output %q)", err, sorted)
	}
	return string(sorted)
}

// Every disagreement gets one row with all three verdicts, and the views that
// agree print nothing: nf_tables is in all three, ghost is in the list and the
// symbol table while the sysfs registry has no kobject for it, and rootkit is in
// sysfs and the symbol table while the list has forgotten it.
func TestHiddenModuleJoinReportsEveryDisagreement(t *testing.T) {
	want := "GAP ghost sysfs=no proc=yes kallsyms=yes symbols 1\n" +
		"HIDDEN rootkit sysfs=yes proc=no kallsyms=yes size 16384 refs 0 state live taint O symbols 2\n"
	if got := HiddenModuleBody(markedModuleStream(true, true)); got != want {
		t.Errorf("the Go join rendered\n%q\nwant\n%q", got, want)
	}
	if got := runsAwkJoin(t, markedModuleStream(true, true)); got != want {
		t.Errorf("the awk join rendered\n%q\nwant\n%q", got, want)
	}
}

// A view that could not be read is unknown, not a verdict: with /sys unmounted
// every module the list names must not become a GAP row, and the sysfs verdict
// reads "?". The symbols only row is what is left, without attributes — they
// come from sysfs, which is the view that is missing.
func TestHiddenModuleJoinMarksAnAbsentViewUnknown(t *testing.T) {
	stream := markedModuleStream(false, true)
	want := "HIDDEN rootkit sysfs=? proc=no kallsyms=yes symbols 2\n"
	if got := HiddenModuleBody(stream); got != want {
		t.Errorf("the Go join rendered\n%q\nwant\n%q", got, want)
	}
	if got := runsAwkJoin(t, stream); got != want {
		t.Errorf("the awk join rendered\n%q\nwant\n%q", got, want)
	}
}

// A name only the symbol table is missing stays out of the report: a kernel
// built without CONFIG_KALLSYMS_ALL tags few of its modules, and those rows
// would bury the ones that matter.
func TestHiddenModuleJoinIsQuietAboutAMissingSymbolTag(t *testing.T) {
	stream := "A sysfs 1\nA kallsyms 1\n" +
		"S nf_tables size 409600\nP nf_tables\n"
	if got := HiddenModuleBody(stream); got != "" {
		t.Errorf("the Go join rendered %q, want nothing", got)
	}
	if got := runsAwkJoin(t, stream); got != "" {
		t.Errorf("the awk join rendered %q, want nothing", got)
	}
}

// A module the symbol table alone carries is the shape a rootkit that also
// dropped its kobject leaves: the row names the view that still has it.
func TestHiddenModuleJoinReportsASymbolOnlyModule(t *testing.T) {
	stream := "A sysfs 1\nA kallsyms 1\nK hidden 3\n"
	want := "HIDDEN hidden sysfs=no proc=no kallsyms=yes symbols 3\n"
	if got := HiddenModuleBody(stream); got != want {
		t.Errorf("the Go join rendered\n%q\nwant\n%q", got, want)
	}
	if got := runsAwkJoin(t, stream); got != want {
		t.Errorf("the awk join rendered\n%q\nwant\n%q", got, want)
	}
}

// A module with no attributes that read back gets no empty tail: the row ends
// after the verdicts.
func TestHiddenModuleJoinPrintsNoEmptyAttributeTail(t *testing.T) {
	stream := "A sysfs 1\nA kallsyms 1\nS rootkit\nK rootkit 2\n"
	want := "HIDDEN rootkit sysfs=yes proc=no kallsyms=yes symbols 2\n"
	if got := HiddenModuleBody(stream); got != want {
		t.Errorf("the Go join rendered\n%q\nwant\n%q", got, want)
	}
	if got := runsAwkJoin(t, stream); got != want {
		t.Errorf("the awk join rendered\n%q\nwant\n%q", got, want)
	}
}
