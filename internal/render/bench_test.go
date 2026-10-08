// The panel is the report's other hot path: every collected check's body goes
// through bodyRows (budget planning, per-line lexing, span painting) and then
// through checkBlock (bounding, padding, wrapping). These benchmarks pin it, so
// a lexer or a layout change that turns rendering quadratic shows up as a
// number instead of as a slow report.

package render

import (
	"strconv"
	"strings"
	"testing"

	"karma/internal/form"
	"karma/internal/model"
	"karma/internal/testkit"
)

// listingPanel is one directory-listing check's result: rows of the collected
// ls -l shape, with the one finding a hidden file in a temporary directory
// leaves when hit is true.
func listingPanel(tb testing.TB, rows int, hit bool) *model.CheckResult {
	tb.Helper()
	check := &model.Check{
		ID: "key-dirs", Aspect: model.AspectFilesystem, Syntax: model.SyntaxLsL,
		Rules: []model.Matcher{
			model.NewRule("hidden-tmp-path", `/?(?:(?:var/)?tmp|dev/shm)/\.[A-Za-z0-9_.-]+`,
				model.High, "hidden file in a temporary directory"),
		},
	}
	var body strings.Builder
	for i := range rows {
		if hit && i == rows/2 {
			body.WriteString("-rwsr-xr-x 1 root root 1100000 Oct 06 02:45 /tmp/.evil\n")
			continue
		}
		body.WriteString("-rw-r--r-- 1 root root 4096 Oct 06 12:00 /etc/hosts\n")
	}
	return &model.CheckResult{
		Check: check, Outcome: model.Collected, ProbeLabel: "find",
		Raw:      body.String(),
		Document: testkit.Analyze(body.String(), check),
	}
}

// BenchmarkCheckPanelListing is a full directory-listing panel at the size the
// checks collect: four hundred rows, the ls-l lexer on every one of them, and
// one finding with its reason.
func BenchmarkCheckPanelListing(b *testing.B) {
	result := listingPanel(b, 400, true)
	b.ReportAllocs()
	for b.Loop() {
		checkPanel(result, 400, 120, true)
	}
}

// BenchmarkCheckPanelQuietRail is the same body with no finding in it, which is
// how most hosts answer: the panel is still drawn, and its head carries no
// reason.
func BenchmarkCheckPanelQuietRail(b *testing.B) {
	result := listingPanel(b, 400, false)
	b.ReportAllocs()
	for b.Loop() {
		checkPanel(result, 400, 120, true)
	}
}

// BenchmarkCheckPanelPlain is the same body on a stream that takes no color:
// a redirected report or a pipe. The panel is the same layout with no escapes,
// so this is the path the plain output pays for and the one the lexers must
// not run on.
func BenchmarkCheckPanelPlain(b *testing.B) {
	result := listingPanel(b, 400, true)
	b.ReportAllocs()
	for b.Loop() {
		checkPanel(result, 400, 120, false)
	}
}

// formPanel is one check drawn through a form: a record set and the table its
// check declares, which is how ps, pstree and top's record fallbacks render.
// The hits are the ones a rule states on the command line column, so the
// painted path carries spans the way a real finding does.
func formPanel(tb testing.TB, rows int) *model.CheckResult {
	tb.Helper()
	check := &model.Check{
		ID: "ps", Aspect: model.AspectProcess,
		Form: form.Table{Align: map[string]form.Alignment{"PID": form.Right}},
		Rules: []model.Matcher{
			model.NewRule("ps-tmp-path", `(?:^|\s)/(?:tmp|var/tmp|dev/shm)/\S*`,
				model.Medium, "command line references temp path"),
		},
	}
	header := []string{"UID", "PID", "PPID", "STIME", "TTY", "TIME", "CMD"}
	set := &model.RecordSet{Header: header}
	for i := range rows {
		values := []string{"root", strconv.Itoa(i), "1", "10:00", "?", "00:00:00", "/usr/sbin/cron -f"}
		if i == rows/2 {
			values[6] = "/tmp/.evil -x"
		}
		fields := make([]model.Field, len(header))
		for index, name := range header {
			fields[index] = model.Field{Name: name, Value: values[index]}
		}
		set.Rows = append(set.Rows, model.Record{Fields: fields})
	}
	return &model.CheckResult{
		Check: check, Outcome: model.Collected, ProbeLabel: "ps",
		Document: testkit.RecordsDocument(set, check),
	}
}

// BenchmarkCheckPanelFormColored and BenchmarkCheckPanelFormPlain are the form
// path — `ps` and its neighbours — on a stream that takes color and on one
// that does not.
func BenchmarkCheckPanelFormColored(b *testing.B) {
	result := formPanel(b, 400)
	b.ReportAllocs()
	for b.Loop() {
		checkPanel(result, 400, 120, true)
	}
}

func BenchmarkCheckPanelFormPlain(b *testing.B) {
	result := formPanel(b, 400)
	b.ReportAllocs()
	for b.Loop() {
		checkPanel(result, 400, 120, false)
	}
}

// BenchmarkPaintLine isolates the span stacker: a row with the ls-l lexer's
// spans for every permission bit, the size, the date and the name.
func BenchmarkPaintLine(b *testing.B) {
	const row = "drwxr-xr-x 2 root root 4096 Oct 06 12:00 /tmp/sub"
	spans := styleLsL(row)
	b.ReportAllocs()
	for b.Loop() {
		paintLine(row, spans)
	}
}
