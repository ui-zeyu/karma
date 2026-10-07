package model

import (
	"regexp"
	"testing"
)

// row is a record whose fields are the given name/value pairs.
func row(pairs ...string) *Record {
	rec := &Record{}
	for index := 0; index+1 < len(pairs); index += 2 {
		rec.Fields = append(rec.Fields, Field{Name: pairs[index], Value: pairs[index+1]})
	}
	return rec
}

// A pattern rule runs its regex over every field's value and states the hit
// where it fell: the span is in the field's own coordinates, so a form paints
// the cell without measuring anything again.
func TestRuleJudgeStatesItsSpansInTheFieldsItMatched(t *testing.T) {
	rule := NewRule("tmp-path", `/(?:tmp|var/tmp)/\S*`, Medium, "temp path")
	rec := row("USER", "root", "PID", "12", "COMMAND", "/usr/bin/x /tmp/p")
	matches := rule.Judge(rec)
	if len(matches) != 1 {
		t.Fatalf("the rule should state one hit, got %+v", matches)
	}
	match := matches[0]
	if len(match.Spans) != 1 || match.Spans[0].Field != 2 {
		t.Fatalf("the hit fell in COMMAND (index 2), got %+v", match.Spans)
	}
	span := match.Spans[0]
	if got := "/usr/bin/x /tmp/p"[span.Start:span.End]; got != "/tmp/p" {
		t.Errorf("the span should be relative to the field's value: %d..%d = %q", span.Start, span.End, got)
	}
	if match.Severity != Medium || match.Message != "temp path" || match.ID != "tmp-path" {
		t.Errorf("the verdict should travel with the spans: %+v", match)
	}
}

// The scan keeps going after a hit, so the same word in two columns lights
// both: one match, one span per column it fell in.
func TestRuleJudgeLightsEveryFieldItMatched(t *testing.T) {
	rule := NewRule("root-path", `\broot\b`, Medium, "root in a cell")
	rec := row("USER", "root", "PID", "12", "COMMAND", "/root/x")
	matches := rule.Judge(rec)
	if len(matches) != 1 || len(matches[0].Spans) != 2 {
		t.Fatalf("the hit should carry a span per field it matched, got %+v", matches)
	}
	if matches[0].Spans[0].Field != 0 || matches[0].Spans[1].Field != 2 {
		t.Errorf("the spans should name the fields they fell in: %+v", matches[0].Spans)
	}
}

// A pattern's anchors bind to each value's own start and end, so a `$` at the
// end of a pattern recognizes a value that ends there, whichever column holds
// it — the last column stops being the only one an anchored pattern reaches.
func TestRuleJudgeAnchorsBindToTheValue(t *testing.T) {
	rule := NewRule("hidden-path", `/tmp/\.\S+$`, Low, "a value that ends in a hidden temp path")
	rec := row("NAME", "/tmp/.cache", "SIZE", "4096")
	matches := rule.Judge(rec)
	if len(matches) != 1 || len(matches[0].Spans) != 1 || matches[0].Spans[0].Field != 0 {
		t.Fatalf("the first column's value ends in the pattern, got %+v", matches)
	}
	if got := "/tmp/.cache"[matches[0].Spans[0].Start:matches[0].Spans[0].End]; got != "/tmp/.cache" {
		t.Errorf("the whole value is the span, got %q", got)
	}
}

// A pattern only ever sees one field's value, so a match that needs two values
// side by side does not exist: the blank that joined them was this package's
// own invention, and no value speaks it.
func TestRuleJudgeCannotMatchAcrossFields(t *testing.T) {
	rule := NewRule("shell", `sh -i`, Critical, "interactive shell")
	rec := row("NAME", "deploy sh", "ARGS", "-i -p 22")
	if matches := rule.Judge(rec); matches != nil {
		t.Errorf("no single value holds the pattern, got %+v", matches)
	}
}

// A line of text has no columns, so it is judged as a one-field record and its
// spans stay where they were: every pattern rule of the catalog keeps working.
func TestPatternRuleJudgesALineOfText(t *testing.T) {
	rule := NewRule("base64", `\bbase64\s+-d\b`, Medium, "base64 decode")
	rec := TextRecord(`alias netstat='base64 -d|sh'`)
	matches := rule.Judge(&rec)
	if len(matches) != 1 || len(matches[0].Spans) != 1 || matches[0].Spans[0].Field != 0 {
		t.Fatalf("a one-field record holds the whole hit, got %+v", matches)
	}
	span := matches[0].Spans[0]
	if got := rec.LineText()[span.Start:span.End]; got != "base64 -d" {
		t.Errorf("span = %q, want base64 -d", got)
	}
}

// The exclusion speaks for the value it matched, and the prefilter still keeps
// a value away from the engine.
func TestRuleJudgeKeepsItsExclusion(t *testing.T) {
	rule := NewRule("hidden", `/tmp/\.\S+`, Low, "hidden file in a temporary directory").
		WithExclude(`/tmp/\.X11-unix`)
	rec := TextRecord("-rw 0 /tmp/.X11-unix")
	if matches := rule.Judge(&rec); matches != nil {
		t.Errorf("the exclusion should keep the value quiet, got %+v", matches)
	}
}

// A predicate states the spans it recognized: a whole value, a substring, or
// what a pattern matched — in every selected field that has one.
func TestFieldPredicatesStateTheirSpans(t *testing.T) {
	rec := row("STAT", "Ss", "USER", "www-data", "COMMAND", "python3 -m http.server 8080")
	cases := []struct {
		name     string
		judgment Judgment
		want     []Span
	}{
		{"a whole field", FieldOneOf{Fields: []string{"STAT"}, Values: []string{"Ss", "Z"}},
			[]Span{FieldSpan(0, 2)}},
		{"a substring", FieldHas{Fields: []string{"COMMAND"}, Sub: "http.server"},
			[]Span{{Field: 2, Start: 11, End: 22}}},
		{"a missing substring", FieldHas{Fields: []string{"COMMAND"}, Sub: "xmrig"}, nil},
		{"a pattern", FieldRegex{Fields: []string{"COMMAND"}, Pattern: regexp.MustCompile(`-m\s+http\.server`)},
			[]Span{{Field: 2, Start: 8, End: 22}}},
		{"one of a set", FieldOneOf{Fields: []string{"USER"}, Values: []string{"www-data", "apache"}},
			[]Span{FieldSpan(1, 8)}},
		{"none of a set", FieldOneOf{Fields: []string{"USER"}, Values: []string{"root"}}, nil},
		{"a column the record lacks", FieldHas{Fields: []string{"UID"}, Sub: "www-data"}, nil},
	}
	for _, tc := range cases {
		spans, ok := tc.judgment.Holds(rec)
		if ok != (len(tc.want) > 0) {
			t.Errorf("%s: holds = %v, want %v", tc.name, ok, len(tc.want) > 0)
			continue
		}
		if len(spans) != len(tc.want) {
			t.Errorf("%s: spans = %+v, want %+v", tc.name, spans, tc.want)
			continue
		}
		for index := range spans {
			if spans[index] != tc.want[index] {
				t.Errorf("%s: spans = %+v, want %+v", tc.name, spans, tc.want)
				break
			}
		}
	}
}

// A selection of several spellings reads whichever the record carries: one
// declaration covers both the auxww columns and System V's, and a record that
// carries neither is quiet.
func TestASelectionNamesSeveralSpellings(t *testing.T) {
	judgment := FieldOneOf{Fields: []string{"USER", "UID"}, Values: []string{"www-data"}}
	for index, rec := range []*Record{
		row("USER", "www-data", "COMMAND", "/bin/sh"),
		row("UID", "www-data", "CMD", "/bin/sh"),
	} {
		spans, ok := judgment.Holds(rec)
		if !ok || len(spans) != 1 {
			t.Fatalf("spelling %d should read its account column, got %+v %v", index, spans, ok)
		}
		if account := rec.Fields[spans[0].Field].Name; account != "USER" && account != "UID" {
			t.Errorf("the span should fall in the column the record carries, got %s", account)
		}
	}
	if _, ok := judgment.Holds(row("COMMAND", "/bin/sh")); ok {
		t.Error("a record with neither column is not what the judgment describes")
	}
}

// An empty selection is the wildcard: the predicate judges every field, which
// is the pattern rule's own selection.
func TestAnEmptySelectionJudgesEveryField(t *testing.T) {
	spans, ok := FieldHas{Sub: "sh"}.Holds(row("NAME", "deploy", "COMMAND", "/bin/sh"))
	if !ok || len(spans) != 1 || spans[0].Field != 1 {
		t.Fatalf("the wildcard should reach every field, got %+v %v", spans, ok)
	}
}

// Judgments combine, and a combination states what its members looked at: the
// account cell at one end, the interpreter word at the other, and no span for
// the columns between them.
func TestJudgmentsCombine(t *testing.T) {
	rec := row("USER", "www-data", "PID", "2210", "COMMAND", "/bin/sh -c id")
	interpreter := regexp.MustCompile(`\b(?:ba|z)?sh\b`)
	judgment := All{
		FieldOneOf{Fields: []string{"USER"}, Values: []string{"www-data"}},
		FieldRegex{Fields: []string{"COMMAND"}, Pattern: interpreter},
	}
	spans, ok := judgment.Holds(rec)
	if !ok {
		t.Fatal("the conjunction should hold")
	}
	if len(spans) != 2 || spans[0] != (Span{Field: 0, Start: 0, End: 8}) ||
		spans[1] != (Span{Field: 2, Start: 5, End: 7}) {
		t.Errorf("the spans should be the members' own, got %+v", spans)
	}
	// One failing member is enough.
	if _, ok := (All{FieldOneOf{Fields: []string{"USER"}, Values: []string{"root"}}, FieldHas{Fields: []string{"COMMAND"}, Sub: "sh"}}).Holds(rec); ok {
		t.Error("a conjunction with a failing member should not hold")
	}
	// Any takes the first member that holds, and Not holds on an absence: what
	// it recognizes cannot be marked, so it states no span.
	if spans, ok := (Any{FieldHas{Fields: []string{"COMMAND"}, Sub: "xmrig"}, FieldHas{Fields: []string{"COMMAND"}, Sub: "-c"}}).Holds(rec); !ok || len(spans) != 1 || spans[0].Field != 2 {
		t.Errorf("Any should take the member that held: %+v %v", spans, ok)
	}
	if spans, ok := (Not{FieldHas{Fields: []string{"COMMAND"}, Sub: "xmrig"}}).Holds(rec); !ok || len(spans) != 0 {
		t.Errorf("Not should hold on an absence with no span: %+v %v", spans, ok)
	}
	if _, ok := (Not{FieldHas{Fields: []string{"COMMAND"}, Sub: "-c"}}).Holds(rec); ok {
		t.Error("Not should not hold when the judgment does")
	}
}

// A compound rule is a Matcher like any other: it names itself and states its
// hit on the spans its judgment recognized.
func TestJudgedStatesTheSpansItJudged(t *testing.T) {
	rule := NewJudged("stat-zombie", Medium, "zombie process", All{
		FieldOneOf{Fields: []string{"STAT"}, Values: []string{"Z"}},
		FieldHas{Fields: []string{"COMMAND"}, Sub: "defunct"},
	})
	if rule.Name() != "stat-zombie" {
		t.Errorf("name = %q", rule.Name())
	}
	zombie := row("STAT", "Z", "COMMAND", "[bash] <defunct>")
	matches := rule.Judge(zombie)
	if len(matches) != 1 {
		t.Fatalf("the rule should state one hit, got %+v", matches)
	}
	if matches[0].Severity != Medium || matches[0].Message != "zombie process" {
		t.Errorf("the verdict should travel: %+v", matches[0])
	}
	if len(matches[0].Spans) != 2 || matches[0].Spans[0].Field != 0 || matches[0].Spans[1].Field != 1 {
		t.Errorf("the hit should carry a span per member: %+v", matches[0].Spans)
	}
	live := row("STAT", "Ss", "COMMAND", "bash")
	if matches := rule.Judge(live); matches != nil {
		t.Errorf("a live process should stay quiet, got %+v", matches)
	}
}
