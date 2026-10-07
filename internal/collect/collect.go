// Package collect is the collector protocol: the one-object-per-check JSON
// stream a collecting karma writes for whoever asked it for a run.
//
// A remote Linux channel collects through a karma binary placed on the target,
// and the operator drives that binary with its own selectors, its concurrency
// and its per-check budget. The answer is a stream of results rather than a
// report: each line carries what the tier read — its own text, or the fields it
// read instead — and how the walk ended, and nothing shaped for a terminal. The operator renders with its own catalog, its
// own rules and its own terminal — so the report of a remote run is the report a
// local run on that host would have drawn, with one implementation of the
// presentation wherever the collection happened.
//
// The stream is in completion order, not catalog order: the checks run
// concurrently and a line is written the moment its check finishes, so the
// operator draws each panel as its result arrives and restores the catalog order
// itself. A reader that sees two lines for one check takes the last; the only
// way that happens is a check whose own result could not be written.
//
// What is deliberately not in a line: the reading (sections, hits, severities),
// the masthead's facts, and the shape of any table. Those are the operator's
// work, and a collector that shipped them would have to be kept in step with the
// presentation it is not part of.
package collect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"karma/internal/model"
	"karma/internal/runner"
)

// Result is one finished check, as it travels. The fields are the ones a
// rendered run keeps of a check's outcome (model.CheckResult) minus the reading:
// the check is named by id because both ends carry the same catalog, and the
// rest is the tier's own text plus how its walk ended.
type Result struct {
	// Check is the check id both ends know from their catalog.
	Check string `json:"check"`
	// Outcome is model.Outcome's own name: collected, skipped or failed.
	Outcome string `json:"outcome"`
	// Probe is the tier that answered, as its label plus any tier the step ran
	// with it ("ss", "reg query a + reg query b"). Empty for a skipped check.
	Probe string `json:"probe,omitempty"`
	// Skipped is the chain of tiers the walk passed before the one that
	// answered, in the order it tried them.
	Skipped []string `json:"skipped,omitempty"`
	// Raw is the tier's stdout exactly as collected, before the reading layer
	// caps or shapes anything. A tier that read fields states them in Fields
	// instead, and the reading takes whichever came.
	Raw string `json:"raw,omitempty"`
	// Fields is a fields tier's answer: the column names and the rows' values,
	// as data. It travels as data because that is what it is — the operator lays
	// the rows out and reads the rules against them — and it is not repeated as
	// text: the readable rendering is derived from it on the far side.
	Fields *Fields `json:"fields,omitempty"`
	// Stderr is what a failing tier wrote, which the panel shows as the note's
	// detail.
	Stderr string `json:"stderr,omitempty"`
	// Note is how the walk ended: the timeout, the interruption, the exit code.
	Note string `json:"note,omitempty"`
	// Truncated marks a body a row cap stopped, so the operator's document keeps
	// the truncation the collector's source saw.
	Truncated bool `json:"truncated,omitempty"`
}

// Fields is a record set as the stream carries it: the column names, and one
// list of values per row. A record's fields are named by the header, so a row
// carries its values alone and the schema is not repeated on every line.
type Fields struct {
	Header []string   `json:"header"`
	Rows   [][]string `json:"rows"`
}

// fieldsOf is a record set in the shape the stream speaks.
func fieldsOf(set *model.RecordSet) *Fields {
	fields := &Fields{Header: set.Header, Rows: make([][]string, 0, len(set.Rows))}
	for _, rec := range set.Rows {
		fields.Rows = append(fields.Rows, rec.Values())
	}
	return fields
}

// records is the set again, its fields named by the header.
func (f *Fields) records() *model.RecordSet {
	set := &model.RecordSet{Header: f.Header, Rows: make([]model.Record, 0, len(f.Rows))}
	for _, values := range f.Rows {
		record := model.Record{Fields: make([]model.Field, len(values))}
		for index, value := range values {
			name := ""
			if index < len(f.Header) {
				name = f.Header[index]
			}
			record.Fields[index] = model.Field{Name: name, Value: value}
		}
		set.Rows = append(set.Rows, record)
	}
	return set
}

// Of is one finished check as it travels.
func Of(result *model.CheckResult) Result {
	out := Result{
		Check:     result.Check.ID,
		Outcome:   result.Outcome.String(),
		Probe:     result.ProbeLabel,
		Skipped:   result.SkippedLabels,
		Stderr:    result.Stderr,
		Note:      result.Note,
		Truncated: result.Document.Truncated,
	}
	// A tier's answer is its text or its fields, and the fields are not also
	// sent as the text they render to: the far side derives that.
	if result.Records != nil {
		out.Fields = fieldsOf(result.Records)
		return out
	}
	out.Raw = result.Raw
	return out
}

// Line is the result as the one line the stream speaks, newline included. HTML
// escaping is off: the text is a target's own output, and turning its `<` and
// `&` into escapes would only make the stream harder to read by eye.
func (r Result) Line() ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode reads one line of the stream: one object, whitespace around it, and
// nothing else (a second object on the line is a producer defect, and json's own
// "invalid character after top-level value" says so). Which check, outcome and
// tier it names is a question only a catalog can answer — that is ToCheckResult.
func Decode(line []byte) (Result, error) {
	var r Result
	if err := json.Unmarshal(line, &r); err != nil {
		return Result{}, err
	}
	return r, nil
}

// ToCheckResult resolves one result against this operator's catalog: the check
// by id, the reading by running the tier's raw text through the same pipeline
// the collecting side would have used, everything else as it arrived. A result
// that names a check, an outcome or a tier this catalog does not carry is an
// error, because half of a report is worse than a run that says it could not
// read its collector.
func ToCheckResult(catalog []*model.Check, r Result, options model.RunOptions) (*model.CheckResult, error) {
	check, ok := CheckByID(catalog, r.Check)
	if !ok {
		return nil, fmt.Errorf("unknown check %q", r.Check)
	}
	outcome, ok := model.ParseOutcome(r.Outcome)
	if !ok {
		return nil, fmt.Errorf("check %s: unknown outcome %q", r.Check, r.Outcome)
	}
	result := &model.CheckResult{
		Check:         check,
		ProbeLabel:    r.Probe,
		SkippedLabels: r.Skipped,
		Outcome:       outcome,
		Raw:           r.Raw,
		Stderr:        r.Stderr,
		Note:          r.Note,
	}
	body := model.Body{Text: r.Raw}
	if r.Fields != nil {
		body.Records = r.Fields.records()
		result.Records = body.Records
		// Evidence is the fields as the lines they read as: derived here, so a
		// line never carries the same answer twice.
		result.Raw = model.RecordsText(body.Records.Rows)
	}
	// A skipped check has no tier and no text; every other outcome names the tier
	// that answered, and its body is read here.
	if r.Probe != "" {
		document, ok := runner.Reading(check, r.Probe, body, r.Truncated, options)
		if !ok {
			return nil, fmt.Errorf("check %s has no tier %q", check.ID, r.Probe)
		}
		result.Document = document
	}
	return result, nil
}

// CheckByID is the catalog lookup both ends of the protocol use.
func CheckByID(catalog []*model.Check, id string) (*model.Check, bool) {
	for _, check := range catalog {
		if check.ID == id {
			return check, true
		}
	}
	return nil, false
}

// Writer is a run's observer in collector mode: one line per check, written when
// that check finishes. Checks finish on their own goroutines, so the lines are
// serialized here; the first write error ends the stream and is kept, because a
// stream with a hole in it is worse than a run that reports it stopped.
type Writer struct {
	mu  sync.Mutex
	w   io.Writer
	err error
}

// NewWriter writes the protocol to w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// CheckStarted is nothing to say: the stream carries finished checks.
func (o *Writer) CheckStarted(*model.Check) {}

// CheckFinished writes one check's line.
func (o *Writer) CheckFinished(_ *model.Check, result *model.CheckResult) {
	line, err := Of(result).Line()
	if err == nil {
		_, err = o.write(line)
	}
	o.remember(err)
}

// Damaged is a check whose presentation broke — a panic in the callback above,
// which is karma's own defect. The consumer gets a failed line naming it, so a
// damaged check is not a check that silently never arrived.
func (o *Writer) Damaged(check *model.Check, err error) {
	line, marshalErr := Result{Check: check.ID, Outcome: model.Failed.String(), Note: err.Error()}.Line()
	if marshalErr == nil {
		_, marshalErr = o.write(line)
	}
	o.remember(marshalErr)
}

// Err is the first error that stopped the stream: a failed write, or a check
// whose line could not be built. A run that ends with one is reported as a run
// whose results could not be delivered.
func (o *Writer) Err() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.err
}

func (o *Writer) write(line []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.err != nil {
		return 0, o.err
	}
	return o.w.Write(line)
}

func (o *Writer) remember(err error) {
	if err == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.err = errors.Join(o.err, err)
}
