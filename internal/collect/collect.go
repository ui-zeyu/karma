// Package collect is the run's result stream: the one-object-per-check JSON a
// run writes when it was asked for JSON instead of a report.
//
// Each line carries what the tier read — its own text, or the fields it read
// instead — and how the walk ended, and nothing shaped for a terminal. The
// stream is in completion order, not catalog order: the checks run concurrently
// and a line is written the moment its check finishes.
//
// What is deliberately not in a line: the reading (sections, hits, severities),
// the masthead's facts, and the shape of any table. Those are the reading
// layer's work, and a stream that shipped them would have to be kept in step
// with the presentation it is not part of.
package collect

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"karma/internal/model"
)

// Result is one finished check, as the stream carries it. The fields are the
// ones a rendered run keeps of a check's outcome (model.CheckResult) minus the
// reading: the check is named by id, and the rest is the tier's own text plus
// how its walk ended.
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
	// Truncated marks a body a row cap stopped, so the reader's document keeps
	// the truncation the source saw.
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

// Writer is a run's observer in JSON mode: one line per check, written when
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
