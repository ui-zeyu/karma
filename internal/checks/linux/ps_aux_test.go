// The aux table's sh tier: the parser's reading of `ps aux --sort`, against a
// real capture's shape. The row wording is procps's; the schema is the native
// tier's PsAuxColumns, which the ps check's rows are drawn in.

package linux

import (
	"testing"

	"karma/internal/checks/linux/native"
)

// psAuxCapture is `LC_ALL=C ps auxww` as procps prints it: the header, kernel
// threads, an account cut to ps's eight-cell column, the two percentages with
// one decimal, a clock start for a process of today and a date for an older
// one, and a command line with its own blanks.
const psAuxCapture = `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168448 13052 ?        Ss   Jul29   0:27 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Jul29   0:00 [kthreadd]
systemd+   442  0.0  0.1  19100  9388 ?        Ss   Jul29   0:11 /sbin/multipathd -d -s
lab      48976  0.3  0.5 797296 44288 ?        Ssl  09:45   0:07 /usr/bin/dbus-daemon --session --address=systemd: --nofork
lab      60557  0.0  0.0  12000  3500 pts/0    R+   10:02   0:00 ps auxww
`

func TestParsePsAuxReadsThePinnedTable(t *testing.T) {
	set, err := psAuxSchema.parse(psAuxCapture)
	if err != nil {
		t.Fatalf("the tier's own capture should parse: %v", err)
	}
	if len(set.Header) != len(native.PsAuxColumns) {
		t.Fatalf("header = %v, want the aux columns", set.Header)
	}
	if len(set.Rows) != 5 {
		t.Fatalf("rows = %d, want 5: %+v", len(set.Rows), set.Rows)
	}
	for _, row := range set.Rows {
		if len(row.Fields) != len(native.PsAuxColumns) {
			t.Fatalf("row fields = %+v, want the declared columns", row.Fields)
		}
		for index, field := range row.Fields {
			if field.Name != native.PsAuxColumns[index] {
				t.Fatalf("field %d named %q, want %q", index, field.Name, native.PsAuxColumns[index])
			}
		}
	}
	// The account keeps ps's eight-cell cut, the kernel thread its brackets,
	// and the command line is the rest of the row with its own blanks.
	row := set.Rows[2]
	for name, want := range map[string]string{
		"USER": "systemd+", "PID": "442", "%CPU": "0.0", "%MEM": "0.1", "VSZ": "19100",
		"RSS": "9388", "TTY": "?", "STAT": "Ss", "START": "Jul29", "TIME": "0:11",
		"COMMAND": "/sbin/multipathd -d -s",
	} {
		if got, _ := row.Value(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if got, _ := set.Rows[1].Value("COMMAND"); got != "[kthreadd]" {
		t.Errorf("kernel thread command = %q, want [kthreadd]", got)
	}
	if got, _ := set.Rows[3].Value("COMMAND"); got != "/usr/bin/dbus-daemon --session --address=systemd: --nofork" {
		t.Errorf("command line = %q", got)
	}
	if got, _ := set.Rows[3].Value("START"); got != "09:45" {
		t.Errorf("today's start = %q, want 09:45", got)
	}
}

// Text the parser does not know is refused rather than guessed at: the System V
// header, a row whose percentage is not a number, and the rows the shared
// reading refuses for both tables.
func TestParsePsAuxDeclinesOtherText(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"no header", "root 1 0.0 0.0 168448 13052 ? Ss Jul29 0:27 /sbin/init\n"},
		{"ef header", psEfHeaderRow + "\nroot 1 0 0 Jul29 ? 00:00:27 /sbin/init\n"},
		{"row cut short", psAuxHeaderRow + "\nroot 1 0.0 0.1 168448 13052 ?\n"},
		{"cpu not a number", psAuxHeaderRow + "\nroot 1 x 0.1 168448 13052 ? Ss Jul29 0:27 /sbin/init\n"},
		{"no command", psAuxHeaderRow + "\nroot 1 0.0 0.1 168448 13052 ? Ss Jul29 0:27\n"},
		{"empty", ""},
	}
	for _, c := range cases {
		if set, err := psAuxSchema.parse(c.text); err == nil {
			t.Errorf("%s: parsed as %+v, want a refusal", c.name, set)
		}
	}
}
