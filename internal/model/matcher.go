// Matchers: a rule is a judgment about a record.
//
// A rule speaks in one vocabulary: a predicate over a selection of the
// record's fields, and combinators over predicates. A pattern rule is a regex
// whose selection is every field; a field rule names its columns, and a
// selection of several spellings reads whichever the record carries. A hit
// states where it fell — the spans, in each field's own coordinates — so a
// consumer paints it without measuring anything again, and nothing formats
// fields into a line to parse that line back out.

package model

import (
	"regexp"
	"slices"
	"strings"
)

// Matcher is one rule of a check. Name is the rule's id: every hit it states
// carries it, and the catalog's invariants (one id per rule, each platform's
// pack apart) read it. Judge states the hits the rule recognizes in one
// record; nil when the record is quiet, so a normal host's rows allocate
// nothing.
type Matcher interface {
	Name() string
	Judge(rec *Record) []Match
}

// Hit is what every matcher states about the hit it recognizes: the rule's
// name, the level it grades the hit at, and the sentence the report says about
// it. The level and the sentence mean what they always meant — the severity
// floor and the trailing reason read them unchanged.
type Hit struct {
	ID       string
	Severity Severity
	Message  string
}

// MakeHit is a Hit from its parts, for the rule declarations where a literal
// reads better at one line: MakeHit("stat-zombie", Medium, "zombie process").
func MakeHit(id string, severity Severity, message string) Hit {
	return Hit{ID: id, Severity: severity, Message: message}
}

// Span is the part of a field a judgment is about: the field's index and a
// byte range inside its value. A judgment that recognizes a value spans all of
// it; one that recognizes a substring or a pattern spans what it matched, so a
// combination of judgments marks exactly what its members looked at.
type Span struct {
	Field int
	Start int
	End   int
}

// FieldSpan is the span of a whole field's value.
func FieldSpan(field, length int) Span { return Span{Field: field, End: length} }

// Judgment is what a rule's body recognizes in a record: whether the record is
// what it describes, and the parts of it that say so.
type Judgment interface {
	Holds(rec *Record) (spans []Span, ok bool)
}

// Name is this rule's id.
func (r Rule) Name() string { return r.ID }

// Judge runs this rule's pattern over every field's value and states one hit
// whose spans are what it matched, in every value it matched. The prefilter is
// this implementation's own accelerator: a value that cannot match never
// reaches the engine.
func (r Rule) Judge(rec *Record) []Match {
	spans := patternSpans(rec, nil, r.Pattern, r.Exclude, r.literals)
	if len(spans) == 0 {
		return nil
	}
	return []Match{{ID: r.ID, Severity: r.Severity, Message: r.Message, Spans: spans}}
}

// Judged is a rule whose judgment is stated outright: any judgment, plus what
// a hit means. NewRule's pattern-over-every-field is the catalog's common
// case; a compound judgment — the account column and the command line
// together — is a rule by saying so here.
type Judged struct {
	Hit
	Judgment
}

// NewJudged builds a rule from any judgment: the shape NewRule's pattern is
// not, stated where the rule declares it.
func NewJudged(id string, severity Severity, message string, judgment Judgment) Judged {
	return Judged{Hit: MakeHit(id, severity, message), Judgment: judgment}
}

// Name is this rule's id.
func (j Judged) Name() string { return j.Hit.ID }

// Judge states the hit on the spans the judgment recognized: the fields and
// the bytes they named, or the record itself when the judgment named none.
func (j Judged) Judge(rec *Record) []Match {
	spans, ok := j.Judgment.Holds(rec)
	if !ok {
		return nil
	}
	return []Match{{ID: j.ID, Severity: j.Severity, Message: j.Message, Spans: spans}}
}

// patternSpans states what a pattern recognized in the selected fields: one
// span per value that matched and cleared the exclusion, in that value's own
// coordinates — the scan keeps going after a hit, so a word in two columns
// lights both. A selection of names reads the columns the record carries and
// skips the ones it lacks.
func patternSpans(rec *Record, selection []string, pattern, exclude *regexp.Regexp, literals []string) []Span {
	var spans []Span
	eachSelected(rec, selection, func(index int, value string) {
		if !prefilterMatches(literals, value) {
			return
		}
		loc := pattern.FindStringIndex(value)
		if loc == nil {
			return
		}
		if exclude != nil && exclude.MatchString(value) {
			return
		}
		spans = append(spans, Span{Field: index, Start: loc[0], End: loc[1]})
	})
	return spans
}

// eachSelected visits the fields a selection names — every field when it names
// none, which is the pattern rule's wildcard. A name the record does not carry
// selects nothing: a body with no such column is not what the rule describes.
func eachSelected(rec *Record, selection []string, visit func(index int, value string)) {
	if len(selection) == 0 {
		for index, field := range rec.Fields {
			visit(index, field.Value)
		}
		return
	}
	for _, name := range selection {
		if index := rec.FieldIndex(name); index >= 0 {
			visit(index, rec.Fields[index].Value)
		}
	}
}

// FieldRegex holds when a selected field's value matches Pattern; its spans
// are what the pattern matched in every selected value that did.
type FieldRegex struct {
	// Fields names the columns judged; empty names every field.
	Fields []string
	// Pattern is the regex each selected value runs through. Its anchors bind
	// to the value's own start and end, so a `$` at the end of a pattern
	// recognizes a value that ends there, whichever column holds it.
	Pattern *regexp.Regexp
	// Exclude voids the values it matches.
	Exclude *regexp.Regexp
}

func (c FieldRegex) Holds(rec *Record) ([]Span, bool) {
	spans := patternSpans(rec, c.Fields, c.Pattern, c.Exclude, nil)
	return spans, len(spans) > 0
}

// FieldHas holds when a selected field's value contains Sub; its spans are the
// first occurrence in every selected value that has it.
type FieldHas struct {
	Fields []string
	Sub    string
}

func (c FieldHas) Holds(rec *Record) ([]Span, bool) {
	var spans []Span
	eachSelected(rec, c.Fields, func(index int, value string) {
		if at := strings.Index(value, c.Sub); at >= 0 {
			spans = append(spans, Span{Field: index, Start: at, End: at + len(c.Sub)})
		}
	})
	return spans, len(spans) > 0
}

// FieldOneOf holds when a selected field's value is one of Values; its spans
// are the whole value of every selected field that is.
type FieldOneOf struct {
	Fields []string
	Values []string
}

func (c FieldOneOf) Holds(rec *Record) ([]Span, bool) {
	var spans []Span
	eachSelected(rec, c.Fields, func(index int, value string) {
		if slices.Contains(c.Values, value) {
			spans = append(spans, FieldSpan(index, len(value)))
		}
	})
	return spans, len(spans) > 0
}

// All holds when every member holds, and its spans are what its members
// recognized — the account cell at one end, the interpreter word at the other,
// with the columns between them untouched.
type All []Judgment

func (c All) Holds(rec *Record) ([]Span, bool) {
	var spans []Span
	for _, member := range c {
		held, ok := member.Holds(rec)
		if !ok {
			return nil, false
		}
		spans = append(spans, held...)
	}
	return spans, true
}

// Any holds when at least one member holds, and its spans are the first
// member's that did.
type Any []Judgment

func (c Any) Holds(rec *Record) ([]Span, bool) {
	for _, member := range c {
		if spans, ok := member.Holds(rec); ok {
			return spans, true
		}
	}
	return nil, false
}

// Not holds when the judgment does not. Its spans are empty: what a negation
// recognizes is an absence, so there is nothing to mark, and the hit reads as
// the reason on the record.
type Not struct {
	Judgment
}

func (c Not) Holds(rec *Record) ([]Span, bool) {
	if _, ok := c.Judgment.Holds(rec); ok {
		return nil, false
	}
	return nil, true
}
