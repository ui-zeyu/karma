// The panel is the report's other hot path: every collected check's body goes
// through bodyRows (budget planning, per-line lexing, span painting) and then
// through checkBlock (bounding, padding, wrapping). These benchmarks pin it, so
// a lexer or a layout change that turns rendering quadratic shows up as a
// number instead of as a slow report.

package render

import (
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/reader"
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
		Document: reader.Analyze(body.String(), check.Rules, check.Filters, 0, model.FloorAll, check.Normalize),
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
