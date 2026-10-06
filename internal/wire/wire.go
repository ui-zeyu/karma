// Package wire is the collector's answer: one JSON document per probe, the
// format a placed collector reports with.
//
// A collector runs one probe at a time and prints the model.RunResult of that
// call, so the operator's pipeline — assemble, adapt, normalize, rules, filters,
// render — reads bytes that are exactly what a local run on the same host would
// have produced. Nothing above the channel has to know which side of the wire
// the collection happened on.

package wire

import (
	"encoding/json"
	"fmt"

	"karma/internal/model"
)

// Envelope is one probe's result on the wire.
//
// The body travels base64 (encoding/json's []byte): a transport may be a pty
// that rewrites line endings, and a body holding newlines and braces must not be
// able to look like the frame's own end. The verdict travels as its name, so a
// line can be read by eye while debugging a target by hand.
type Envelope struct {
	Check     string `json:"check"`
	Probe     string `json:"probe"`
	Verdict   string `json:"verdict"`
	ExitCode  int    `json:"exit"`
	Truncated bool   `json:"truncated,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
	Stdout    []byte `json:"stdout"`
}

// New frames one call's result by the names the operator asked with.
func New(check, probe string, result model.RunResult) Envelope {
	return Envelope{
		Check:     check,
		Probe:     probe,
		Verdict:   result.Verdict.String(),
		ExitCode:  result.ExitCode,
		Truncated: result.Truncated,
		Stderr:    result.Stderr,
		Stdout:    []byte(result.Stdout),
	}
}

// Result reads the envelope back into the domain type. An unknown verdict name
// is an error rather than a fallback: the two ends are one build, so a name this
// one does not know means they are not.
func (e Envelope) Result() (model.RunResult, error) {
	verdict, ok := verdictByName[e.Verdict]
	if !ok {
		return model.RunResult{}, fmt.Errorf("unknown verdict %q", e.Verdict)
	}
	return model.RunResult{
		Verdict:   verdict,
		Stdout:    string(e.Stdout),
		Stderr:    e.Stderr,
		ExitCode:  e.ExitCode,
		Truncated: e.Truncated,
	}, nil
}

// Line renders the envelope as one newline-terminated JSON line: the framing is
// the line, so a reader can take one answer at a time off a stream.
func (e Envelope) Line() ([]byte, error) {
	line, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(line, '\n'), nil
}

// Decode reads one line back; surrounding whitespace is the transport's
// business, so a line already trimmed is read the same as one that is not.
func Decode(line []byte) (Envelope, error) {
	var envelope Envelope
	if err := json.Unmarshal(line, &envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

// verdictByName is the wire spelling of every verdict, keyed by the name
// Verdict.String prints. wire_test pins the table against the constants, so a
// verdict added without a spelling fails there instead of on a target.
var verdictByName = map[string]model.Verdict{
	model.VerdictFailed.String():      model.VerdictFailed,
	model.VerdictAnswered.String():    model.VerdictAnswered,
	model.VerdictUnavailable.String(): model.VerdictUnavailable,
	model.VerdictTimedOut.String():    model.VerdictTimedOut,
	model.VerdictInterrupted.String(): model.VerdictInterrupted,
}
