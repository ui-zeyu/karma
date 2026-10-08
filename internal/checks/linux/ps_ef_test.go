// The ps command's sh tier: the parser's reading of `ps -ef`, against a real
// capture from the lab.

package linux

import (
	"strings"
	"testing"

	"karma/internal/checks/linux/native"
	"karma/internal/model"
)

// psEfCapture is `LC_ALL=C ps -ef` as the lab printed it (2026-10-07): the
// header, kernel threads, an account column cut to eight cells, a command line
// with its own blanks, and the two STIME spellings — a clock for a process
// started today, the date for one from an earlier day.
// psEfHeaderRow is the header line the schema spells, as procps prints it
// (`ps -efww` prints this same header).
const psEfHeaderRow = "UID          PID    PPID  C STIME TTY          TIME CMD"

// psAuxHeaderRow is the aux table's header line, as procps prints it.
const psAuxHeaderRow = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"

const psEfCapture = `UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 Jul29 ?        00:00:27 /sbin/init
root           2       0  0 Jul29 ?        00:00:00 [kthreadd]
systemd+     442       1  0 Jul29 ?        00:00:11 /sbin/multipathd -d -s
lab        44632   44631  0 Jul29 ?        00:00:00 (sd-pam)
lab        48976   44631  0 Jul29 ?        00:00:00 /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation
root       60557     838  0 09:45 ?        00:00:00 sshd: lab [priv]
lab        60610   60604  0 09:45 ?        00:00:00 ps -ef
`

func TestParsePsEfReadsThePinnedTable(t *testing.T) {
	set, err := psEfSchema.parse(psEfCapture)
	if err != nil {
		t.Fatalf("the tier's own capture should parse: %v", err)
	}
	if len(set.Header) != len(native.PsEfColumns) {
		t.Fatalf("header = %v, want the System V columns", set.Header)
	}
	if len(set.Rows) != 7 {
		t.Fatalf("rows = %d, want 7: %+v", len(set.Rows), set.Rows)
	}
	for _, row := range set.Rows {
		if len(row.Fields) != len(native.PsEfColumns) {
			t.Fatalf("row fields = %+v, want the declared columns", row.Fields)
		}
		for index, field := range row.Fields {
			if field.Name != native.PsEfColumns[index] {
				t.Fatalf("field %d named %q, want %q", index, field.Name, native.PsEfColumns[index])
			}
		}
	}
	// The kernel thread keeps the brackets the kernel itself prints, and the
	// account cell keeps ps's eight-cell cut.
	if got, _ := set.Rows[1].Value("UID"); got != "root" {
		t.Errorf("kernel thread account = %q, want root", got)
	}
	if got, _ := set.Rows[2].Value("UID"); got != "systemd+" {
		t.Errorf("a long account keeps ps's cut: %q", got)
	}
	if got, _ := set.Rows[1].Value("CMD"); got != "[kthreadd]" {
		t.Errorf("kernel thread command = %q, want [kthreadd]", got)
	}
	// A command line is the rest of the row: its own blanks and every word of
	// it (the dbus row is the longest one in the capture).
	if got, _ := set.Rows[4].Value("CMD"); got != "/usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation" {
		t.Errorf("command line = %q", got)
	}
	// Both STIME spellings survive, and an sshd row's command line with its
	// bracketed privilege marker.
	if got, _ := set.Rows[0].Value("STIME"); got != "Jul29" {
		t.Errorf("old start = %q, want Jul29", got)
	}
	if got, _ := set.Rows[6].Value("STIME"); got != "09:45" {
		t.Errorf("today's start = %q, want 09:45", got)
	}
	if got, _ := set.Rows[5].Value("CMD"); got != "sshd: lab [priv]" {
		t.Errorf("sshd command = %q", got)
	}
	if got, _ := set.Rows[3].Value("CMD"); got != "(sd-pam)" {
		t.Errorf("parenthesized command = %q", got)
	}
	// The time cell is hours:minutes:seconds, and the two links are the tree's.
	row := set.Rows[0]
	for name, want := range map[string]string{
		"PID": "1", "PPID": "0", "C": "0", "TTY": "?", "TIME": "00:00:27",
	} {
		if got, _ := row.Value(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// The row the parser reads is the row the native tier spells: this is the one
// the /proc read's own row-shape test pins (native.TestPsEfRowShape), so the two
// sources are held to one spelling from both sides.
func TestParsePsEfAgreesWithTheNativeRow(t *testing.T) {
	const row = "root 2210 948 0 14:00 pts/0 00:00:09 bash -i"
	set, err := psEfSchema.parse(psEfHeaderRow + "\n" + row + "\n")
	if err != nil {
		t.Fatalf("the native row spelling should parse: %v", err)
	}
	want := map[string]string{
		"UID": "root", "PID": "2210", "PPID": "948", "C": "0", "STIME": "14:00",
		"TTY": "pts/0", "TIME": "00:00:09", "CMD": "bash -i",
	}
	for name, value := range want {
		if got, _ := set.Rows[0].Value(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

// Text the parser does not know is refused rather than guessed at: a foreign
// header (busybox ps), a missing header, and a row whose links are not pids.
func TestParsePsEfDeclinesOtherText(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"no header", "root 1 0 0 Jul29 ? 00:00:00 /sbin/init\n"},
		{"busybox header", "PID   USER     TIME  COMMAND\n    1 root      0:00 init\n"},
		{"aux header", "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"},
		{"row cut short", psEfHeaderRow + "\nroot 1 0 0 Jul29 ?\n"},
		{"link not a pid", psEfHeaderRow + "\nroot 1 x 0 Jul29 ? 00:00:00 /sbin/init\n"},
		{"no command", psEfHeaderRow + "\nroot 1 0 0 Jul29 ? 00:00:00\n"},
		{"empty", ""},
		// BSD's ps prints the same eight header names with another dialect
		// under them (macOS: a numeric uid, "29Sep26", "??", "100:14.77").
		{"bsd dialect", psEfHeaderRow + "\n0 1 0 0 29Sep26 ?? 100:14.77 /sbin/launchd\n"},
		{"bsd dialect, long row", psEfHeaderRow + "\n501 77448 74783 0 30Sep26 ttys004 0:00.29 -zsh\n"},
	}
	for _, c := range cases {
		if set, err := psEfSchema.parse(c.text); err == nil {
			t.Errorf("%s: parsed as %+v, want a refusal", c.name, set)
		}
	}
}

// The parser's rows read as records the reading layer can judge: a rule that
// names a field paints the same cells whichever source read the table.
func TestParsePsEfRowsAreRecords(t *testing.T) {
	set, err := psEfSchema.parse(psEfCapture)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	matches := model.NewJudged("probe", model.Medium, "m", model.All{
		model.FieldOneOf{Fields: []string{"UID"}, Values: []string{"lab"}},
		model.FieldHas{Fields: []string{"CMD"}, Sub: "dbus-daemon"},
	}).Judge(&set.Rows[4])
	if len(matches) != 1 || len(matches[0].Spans) != 2 {
		t.Fatalf("the rule should light the account and the command line: %+v", matches)
	}
	for _, span := range matches[0].Spans {
		if span.Field != 0 && span.Field != len(native.PsEfColumns)-1 {
			t.Errorf("span landed on field %d of %v", span.Field, set.Header)
		}
	}
	if text := model.RecordsText(set.Rows); !strings.Contains(text, "[kthreadd]") {
		t.Errorf("the readable rendering should carry the rows: %q", text)
	}
}
