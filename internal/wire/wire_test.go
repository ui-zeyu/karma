package wire

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"karma/internal/model"
)

// everyVerdict is the wire's whole vocabulary; a verdict that is missing here is
// one Result cannot read back.
var everyVerdict = []model.Verdict{
	model.VerdictFailed,
	model.VerdictAnswered,
	model.VerdictUnavailable,
	model.VerdictTimedOut,
	model.VerdictInterrupted,
}

func TestVerdictTableCoversTheVocabulary(t *testing.T) {
	if len(verdictByName) != len(everyVerdict) {
		t.Fatalf("the table holds %d names for %d verdicts", len(verdictByName), len(everyVerdict))
	}
	for _, verdict := range everyVerdict {
		name, ok := verdictByName[verdict.String()]
		if !ok || name != verdict {
			t.Fatalf("%v (%q) does not round-trip: %v, %v", verdict, verdict.String(), name, ok)
		}
	}
}

func TestEnvelopeRoundTripsEveryField(t *testing.T) {
	// A body with the frame's own punctuation in it: newlines, braces, quotes and
	// a backslash must come back byte for byte.
	body := "{\"a\":1}\n/sbin/init\n\ttabbed \"quoted\" \\slash\\\n"
	for _, verdict := range everyVerdict {
		result := model.RunResult{
			Verdict:   verdict,
			Stdout:    body,
			Stderr:    "permission denied\n",
			ExitCode:  3,
			Truncated: true,
		}
		line, err := New("listen", "ss", result).Line()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Count(line, []byte("\n")) != 1 || !bytes.HasSuffix(line, []byte("\n")) {
			t.Fatalf("a line holds one frame: %q", line)
		}
		envelope, err := Decode(line)
		if err != nil {
			t.Fatal(err)
		}
		if envelope.Check != "listen" || envelope.Probe != "ss" {
			t.Fatalf("the addressing must survive: %+v", envelope)
		}
		back, err := envelope.Result()
		if err != nil {
			t.Fatal(err)
		}
		if back != result {
			t.Fatalf("%v: the result came back as %+v, want %+v", verdict, back, result)
		}
	}
}

func TestEnvelopeOmitsWhatIsEmpty(t *testing.T) {
	// An answered empty body is a whole answer — a verifier with nothing to
	// report — and the line is then the addressing and the verdict alone.
	line, err := New("listen", "ss", model.RunResult{Verdict: model.VerdictAnswered}).Line()
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"stderr", "truncated"} {
		if strings.Contains(string(line), absent) {
			t.Fatalf("%s belongs on a line only when it has something to say: %s", absent, line)
		}
	}
	envelope, err := Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	result, err := envelope.Result()
	if err != nil {
		t.Fatal(err)
	}
	// The empty body is the answer the operator must be able to tell from a
	// missing one, so the verdict is what says it.
	if result.Stdout != "" || result.Verdict != model.VerdictAnswered {
		t.Fatalf("an empty answer came back as %+v", result)
	}
}

func TestEnvelopeLineIsJSON(t *testing.T) {
	line, err := New("kernel", "tainted", model.RunResult{Verdict: model.VerdictAnswered, Stdout: "0\n"}).Line()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		t.Fatalf("the frame must be JSON: %v", err)
	}
	if raw["verdict"] != "answered" || raw["check"] != "kernel" {
		t.Fatalf("the frame names the verdict and the addressing: %v", raw)
	}
}

func TestDecodeRejectsWhatIsNotAFrame(t *testing.T) {
	for _, line := range []string{
		"",
		"karma: something went wrong\n",
		"{\"check\":\"listen\"",         // truncated
		"[{\"check\":\"listen\"}]",      // a list, not a frame
		"echo of the command I typed\n", // a pty's own noise
	} {
		if _, err := Decode([]byte(line)); err == nil {
			t.Fatalf("%q is not a frame and must not decode", line)
		}
	}
}

func TestResultRejectsAnUnknownVerdict(t *testing.T) {
	envelope := Envelope{Check: "listen", Probe: "ss", Verdict: "maybe"}
	if _, err := envelope.Result(); err == nil || !strings.Contains(err.Error(), "maybe") {
		t.Fatalf("a name this build does not know is a mismatch, got %v", err)
	}
}
