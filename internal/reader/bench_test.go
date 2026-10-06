package reader_test

import (
	"strings"
	"testing"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/reader"
)

// BenchmarkAnalyzeListing measures the reading pipeline on its bulk case: a
// directory listing of twenty thousand rows read against the shipped global rule
// pack and the blank-line filter (hits are rare, as on a normal host). The rules
// are the catalog's own — a copy of them here would measure patterns no check
// carries, and drift as the pack changes.
func BenchmarkAnalyzeListing(b *testing.B) {
	rules := define.GlobalRules
	filters := []model.LineFilter{model.NewFilter("blank", `^[ \t\r]*$`, model.FilterDrop)}

	var body strings.Builder
	for i := 0; i < 20000; i++ {
		body.WriteString("-rw-r--r--  1 root root     4096 Mar 15 10:20 report-")
		body.WriteString(strings.Repeat("x", i%7+1))
		body.WriteString(".log\n")
	}
	text := body.String()

	b.ReportAllocs()
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		if len(reader.Analyze(text, rules, filters, 0, model.FloorAll, nil).Sections) == 0 {
			b.Fatal("no sections")
		}
	}
}
