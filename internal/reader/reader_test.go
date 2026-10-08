package reader_test

import (
	"slices"
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/reader"
)

// readDocument is the reading shortcut for a body of one untitled section.
func readDocument(text string, rules []model.Matcher, filters []model.LineFilter, normalize model.Normalizer) model.Document {
	return reader.Analyze(text, rules, filters, 0, model.FloorAll, normalize)
}

// readSections reads a body the collection states: the pairs are
// (title, text), in order, exactly as the tiers hand them over.
func readSections(rules []model.Matcher, filters []model.LineFilter, normalize model.Normalizer, parts ...string) model.Document {
	body := model.Body{}
	for index := 0; index+1 < len(parts); index += 2 {
		body.Sections = append(body.Sections, model.BodySection{Title: parts[index], Text: parts[index+1]})
	}
	check := &model.Check{Rules: rules, Filters: filters, Normalize: normalize}
	return reader.Read(model.ReadRequest{Check: check, Body: body, Floor: model.FloorAll})
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

func TestReadKeepsTheSectionsTheCollectionStated(t *testing.T) {
	rules := []model.Matcher{rule("root-line", `^root:`, model.High)}
	document := readSections(rules, nil, nil,
		"/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nplain line\n",
		"beyond preamble", "another\n")
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

// A line of a section's own text opens nothing: the boundary is the collection's
// statement, so a file that contains the header spelling stays one section.
func TestReadDoesNotSplitOnContent(t *testing.T) {
	document := readSections(nil, nil, nil,
		"crontab", "MAILTO=root\n== /etc/passwd\n0 * * * * curl x\n")
	if len(document.Sections) != 1 {
		t.Fatalf("a body line never opens a section: %+v", document.Sections)
	}
	if got := len(document.Sections[0].Lines); got != 3 {
		t.Fatalf("the section keeps its three lines, got %d", got)
	}
}

func TestReadMatchesOnTheTitle(t *testing.T) {
	rules := []model.Matcher{rule("authkeys", `authorized_keys`, model.Medium)}
	document := readSections(rules, nil, nil, "/root/authorized_keys", "ssh-ed25519 AAAA comment\n")
	if len(document.Sections) != 1 || len(document.Sections[0].TitleMatches) != 1 {
		t.Fatalf("title should match the rule: %+v", document.Sections)
	}
}

func TestExcludeSuppressesMatch(t *testing.T) {
	rule := rule("uid0", `^[^:]+:[^:]*:0:0:`, model.Critical).WithExclude(`^root:`)
	document := readDocument("root:x:0:0:r:/root:/bin/sh\nbackdoor:x:0:0::/:/bin/sh\n", []model.Matcher{rule}, nil, nil)
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
	rules := []model.Matcher{rule("boom", `boom`, model.High)}
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
				{Line: 0, Match: model.Match{ID: "note", Severity: model.High, Message: "normalize verdict",
					Spans: []model.Span{{Start: 0, End: 9}}}},
			},
		}
	}
	document := readSections(nil, nil, normalize, "section", "original\n")
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
	document := readSections(nil, nil, normalize, "ok", "fine\n", "bad", "boom line\n")
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
	document := readSections(nil, []model.LineFilter{drop(`^\s*$`)}, nil, "empty", "\n\n", "full", "content\n")
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
	rules := []model.Matcher{
		rule("low", `hit`, model.Low),
		rule("benign", `hit`, model.Benign),
	}
	document := readDocument("hit\n", rules, nil, nil)
	if got := document.Sections[0].Lines[0].Severity; got != model.Low {
		t.Fatalf("multiple matches take the most severe: %v", got)
	}
}

// The parts a body carries inside one answer are sections like any other: the
// collection declares the titles, the reading opens a section at each one, and
// the title line becomes the section's title rather than one of its rows.
func TestReadSplitsABodyAtItsDeclaredTitles(t *testing.T) {
	body := model.Body{Sections: []model.BodySection{{
		Title:  "preamble",
		Titles: []string{"file", "ls"},
		Text:   "before\nfile\n/path: ELF\nls\n-rw-r--r-- 1 root root /path\n",
	}}}
	document := reader.Read(model.ReadRequest{
		Check: &model.Check{ID: "pkg-verify"}, Body: body, Floor: model.FloorAll,
	})
	var got []string
	for _, section := range document.Sections {
		for _, line := range section.Lines {
			got = append(got, section.Title+"|"+line.Text)
		}
	}
	want := []string{"preamble|before", "file|/path: ELF", "ls|-rw-r--r-- 1 root root /path"}
	if !slices.Equal(got, want) {
		t.Fatalf("declared titles split the body as\n%q\nwant\n%q", got, want)
	}
}

// A declared title with no rows under it is not a section: the collection prints
// a title only in front of rows it has, and one that arrived anyway keeps nothing
// to show.
func TestReadDropsADeclaredTitleWithNothingUnderIt(t *testing.T) {
	body := model.Body{Sections: []model.BodySection{{
		Titles: []string{"file", "ls"},
		Text:   "file\n/path: ELF\nls\n",
	}}}
	document := reader.Read(model.ReadRequest{
		Check: &model.Check{ID: "pkg-verify"}, Body: body, Floor: model.FloorAll,
	})
	if len(document.Sections) != 1 || document.Sections[0].Title != "file" {
		t.Fatalf("only the title with rows is a section: %+v", document.Sections)
	}
}
