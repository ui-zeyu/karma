package reader_test

import (
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/reader"
)

// readDocument is the reading shortcut the tests use.
func readDocument(text string, rules []model.Rule, filters []model.LineFilter, normalize model.Normalizer) model.Document {
	return reader.Analyze(text, rules, filters, 0, model.FloorAll, normalize)
}

func rule(id, pattern string, severity model.Severity) model.Rule {
	return model.NewRule(id, pattern, severity, id+" reason")
}

func drop(pattern string) model.LineFilter {
	return model.NewFilter("drop-"+pattern, pattern, model.FilterDrop)
}
func keep(pattern string) model.LineFilter {
	return model.NewFilter("keep-"+pattern, pattern, model.FilterKeep)
}

func TestAnalyzeMatchesAndSections(t *testing.T) {
	text := "== /etc/passwd\nroot:x:0:0:root:/root:/bin/bash\nplain line\n== beyond preamble\nanother\n"
	rules := []model.Rule{rule("root-line", `^root:`, model.High)}
	document := readDocument(text, rules, nil, nil)
	if len(document.Sections) != 2 {
		t.Fatalf("section count: %d, want 2", len(document.Sections))
	}
	first := document.Sections[0]
	if first.Title != "/etc/passwd" || len(first.Lines) != 2 {
		t.Fatalf("wrong first-section shape: %q %d lines", first.Title, len(first.Lines))
	}
	if first.Lines[0].Severity != model.High || len(first.Lines[0].Matches) != 1 {
		t.Fatalf("root line should match high: %v", first.Lines[0])
	}
	if first.Lines[1].Severity != model.Info {
		t.Fatalf("plain line should have no severity: %v", first.Lines[1].Severity)
	}
	// the title also runs rules: /etc/passwd has no root: prefix, so no match
	if len(first.TitleMatches) != 0 {
		t.Fatalf("title should not match: %v", first.TitleMatches)
	}
}

func TestAnalyzeTitleMatches(t *testing.T) {
	text := "== /root/authorized_keys\nssh-ed25519 AAAA comment\n"
	rules := []model.Rule{rule("authkeys", `authorized_keys`, model.Medium)}
	document := readDocument(text, rules, nil, nil)
	if len(document.Sections) != 1 || len(document.Sections[0].TitleMatches) != 1 {
		t.Fatalf("title should match the rule: %+v", document.Sections)
	}
}

func TestExcludeSuppressesMatch(t *testing.T) {
	rule := rule("uid0", `^[^:]+:[^:]*:0:0:`, model.Critical).WithExclude(`^root:`)
	document := readDocument("root:x:0:0:r:/root:/bin/sh\nbackdoor:x:0:0::/:/bin/sh\n", []model.Rule{rule}, nil, nil)
	lines := document.Sections[0].Lines
	if len(lines[0].Matches) != 0 {
		t.Fatalf("root line should be excluded: %v", lines[0].Matches)
	}
	if len(lines[1].Matches) != 1 {
		t.Fatalf("backdoor line should match: %v", lines[1].Matches)
	}
}

func TestDropFilterCountsHiddenLines(t *testing.T) {
	text := "keep me\nhide this\nhide that\nvisible\n"
	document := readDocument(text, nil, []model.LineFilter{drop(`^hide `)}, nil)
	if len(document.Sections[0].Lines) != 2 {
		t.Fatalf("should keep two lines: %d", len(document.Sections[0].Lines))
	}
	if len(document.Filtered) != 1 || document.Filtered[0].Count != 2 {
		t.Fatalf("wrong filter count: %+v", document.Filtered)
	}
	// filtered lines still occupy line numbers
	if document.Sections[0].Lines[1].Number != 4 {
		t.Fatalf("visible line numbers should accumulate across filtered lines: %d", document.Sections[0].Lines[1].Number)
	}
}

func TestKeepFilterWhitelists(t *testing.T) {
	text := "one\ntarget line\nthree\nalso target\n"
	document := readDocument(text, nil, []model.LineFilter{keep(`target`)}, nil)
	rows := document.Sections[0].Lines
	if len(rows) != 2 || rows[0].Text != "target line" || rows[1].Text != "also target" {
		t.Fatalf("keep should leave only matching lines: %+v", rows)
	}
	if document.Filtered[0].Count != 2 {
		t.Fatalf("keep hidden count: %+v", document.Filtered)
	}
}

func TestSignalLineSurvivesKeepFilter(t *testing.T) {
	rules := []model.Rule{rule("boom", `boom`, model.High)}
	text := "noise\nboom found\nnoise\n"
	document := readDocument(text, rules, []model.LineFilter{keep(`target`)}, nil)
	// lines with a signal match are exempt from keep filtering
	if len(document.Sections[0].Lines) != 1 || document.Sections[0].Lines[0].Text != "boom found" {
		t.Fatalf("signal line should stay: %+v", document.Sections[0].Lines)
	}
}

func TestNormalizeProducesNotes(t *testing.T) {
	normalize := func(title, body string) *model.Shaped {
		return &model.Shaped{
			Text: "rewritten",
			Notes: []model.LineMatch{
				{Line: 0, Match: model.Match{ID: "note", Severity: model.High, Message: "normalize verdict", Start: 0, End: 9}},
			},
		}
	}
	document := readDocument("== section\noriginal\n", nil, nil, normalize)
	lines := document.Sections[0].Lines
	if len(lines) != 1 || lines[0].Text != "rewritten" {
		t.Fatalf("normalize should rewrite the body: %+v", lines)
	}
	if lines[0].Severity != model.High {
		t.Fatalf("shaper ranges should grade the line: %v", lines[0].Severity)
	}
}

func TestNormalizePanicFallsBackToRawSection(t *testing.T) {
	normalize := func(title, body string) *model.Shaped {
		if strings.Contains(body, "boom") {
			panic("odd row shape")
		}
		return &model.Shaped{Text: "rewritten"}
	}
	document := readDocument("== ok\nfine\n== bad\nboom line\n", nil, nil, normalize)
	if len(document.Sections) != 2 {
		t.Fatalf("both sections should be kept: %d", len(document.Sections))
	}
	if document.Sections[0].Lines[0].Text != "rewritten" {
		t.Fatalf("the normal section is still shaped: %q", document.Sections[0].Lines[0].Text)
	}
	if document.Sections[1].Lines[0].Text != "boom line" {
		t.Fatalf("the panicked section should use the original text: %q", document.Sections[1].Lines[0].Text)
	}
}

func TestEmptySectionsDropped(t *testing.T) {
	text := "== empty\n\n\n== full\ncontent\n"
	document := readDocument(text, nil, []model.LineFilter{drop(`^\s*$`)}, nil)
	if len(document.Sections) != 1 || document.Sections[0].Title != "full" {
		t.Fatalf("empty sections should be dropped: %+v", document.Sections)
	}
}

func TestCapBytesTruncatesOnRuneBoundary(t *testing.T) {
	text := strings.Repeat("a", reader.MaxScanBytes) + "→"
	document := reader.Analyze(text, nil, nil, 0, model.FloorAll, nil)
	if !document.Truncated {
		t.Fatal("over limit should mark truncated")
	}
	lines := document.Sections[0].Lines
	if body := lines[len(lines)-1].Text; strings.Contains(body, "\uFFFD") {
		t.Fatal("partial bytes at the cut point should be dropped entirely")
	}
}

func TestSeverityTakesMinimum(t *testing.T) {
	rules := []model.Rule{
		rule("low", `hit`, model.Low),
		rule("benign", `hit`, model.Benign),
	}
	document := readDocument("hit\n", rules, nil, nil)
	if got := document.Sections[0].Lines[0].Severity; got != model.Low {
		t.Fatalf("multiple matches take the most severe: %v", got)
	}
}
