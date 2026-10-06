package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/wire"
)

// probeCatalog is a stand-in catalog: one check per shape the wire has to
// carry. A Command runs wherever the test does; a Dual with only a script side
// is a tier the local channel does not carry; a body that refuses is the tier's
// own report that it cannot run here.
func probeCatalog() []*model.Check {
	return []*model.Check{
		define.LinuxCheck("demo", "Demo", model.AspectSystem, []model.Step{
			{{Label: "echo", Inv: model.NewCommand("echo", "hello")}},
			{{Label: "noisy", Inv: model.NewCommand("sh", "-c", "echo out; echo err >&2; exit 3")}},
			{{Label: "silent", Inv: model.NewCommand("sh", "-c", "echo why >&2; exit 9")}},
			{{Label: "script-only", Inv: model.Dual{Script: "echo from-the-script-side"}}},
			{{Label: "unavailable", Inv: model.Dual{Run: func(context.Context) (string, error) {
				return "", model.ErrTierUnavailable
			}}}},
			{{Label: "broken", Inv: model.Dual{Run: func(context.Context) (string, error) {
				return "", errors.New("the body gave up")
			}}}},
		}, define.CheckOpt{}),
	}
}

// answerProbe runs one probe through the mode and returns what the operator
// would see: the body on stdout, the human summary on stderr.
func answerProbe(t *testing.T, check, label string, asJSON bool) (string, string, error) {
	t.Helper()
	var out, warn bytes.Buffer
	err := runProbe(context.Background(), &out, &warn, probeCatalog(), check, label, asJSON)
	return out.String(), warn.String(), err
}

func TestProbePrintsTheBodyAndTheVerdict(t *testing.T) {
	out, warn, err := answerProbe(t, "demo", "echo", false)
	if err != nil {
		t.Fatal(err)
	}
	if out != "hello\n" {
		t.Fatalf("the body is printed as it stands, got %q", out)
	}
	if want := "probe demo echo: answered (exit 0)\n"; warn != want {
		t.Fatalf("the summary goes to stderr as %q, got %q", want, warn)
	}
}

// A tier that failed with nothing on stdout is a failure; one that printed while
// exiting non-zero is an answer, exit code and all. The distinction is the whole
// fallback chain's contract, so the wire must carry both.
func TestProbeCarriesTheSilentAndTheNoisyFailure(t *testing.T) {
	out, warn, err := answerProbe(t, "demo", "noisy", false)
	if err != nil {
		t.Fatal(err)
	}
	if out != "out\n" || !strings.Contains(warn, "answered (exit 3)") {
		t.Fatalf("a non-zero exit with stdout is an answer: %q / %q", out, warn)
	}

	out, warn, err = answerProbe(t, "demo", "silent", false)
	if err != nil {
		t.Fatal(err)
	}
	if out != "" || !strings.Contains(warn, "failed (exit 9)") {
		t.Fatalf("a non-zero exit with nothing on stdout is not an answer: %q / %q", out, warn)
	}
}

// A tier the local channel does not carry answers the 127 a missing binary
// gives, with an empty body: that is what the operator's walk reads to fall to
// the next tier.
func TestProbeAnswersUnavailableForATierThisChannelLacks(t *testing.T) {
	out, warn, err := answerProbe(t, "demo", "script-only", true)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := wire.Decode([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	result, err := envelope.Result()
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != model.VerdictUnavailable || result.ExitCode != 127 || result.Stdout != "" {
		t.Fatalf("a missing tier must read as unavailable/127: %+v", result)
	}
	if warn != "" {
		t.Fatalf("the wire form says everything on stdout: %q", warn)
	}
}

func TestProbeAnswersUnavailableForABodyThatCannotRunHere(t *testing.T) {
	out, _, err := answerProbe(t, "demo", "unavailable", true)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := wire.Decode([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	result, err := envelope.Result()
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != model.VerdictUnavailable || result.ExitCode != 127 {
		t.Fatalf("a body that cannot run here is unavailable too: %+v", result)
	}
}

func TestProbeAnswersFailedForABodyThatBroke(t *testing.T) {
	out, _, err := answerProbe(t, "demo", "broken", true)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := wire.Decode([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	result, err := envelope.Result()
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != model.VerdictFailed || !strings.Contains(result.Stderr, "gave up") {
		t.Fatalf("a body that gave up is a failed tier that names why: %+v", result)
	}
}

func TestProbeJSONIsOneLineOfTheWireFormat(t *testing.T) {
	out, warn, err := answerProbe(t, "demo", "noisy", true)
	if err != nil {
		t.Fatal(err)
	}
	if warn != "" {
		t.Fatalf("the wire form writes nothing to stderr: %q", warn)
	}
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("one answer is one line: %q", out)
	}
	envelope, err := wire.Decode([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Check != "demo" || envelope.Probe != "noisy" {
		t.Fatalf("the frame carries the addressing the operator asked with: %+v", envelope)
	}
	result, err := envelope.Result()
	if err != nil {
		t.Fatal(err)
	}
	// The stderr a pty would otherwise merge into the body arrives as its own
	// field, and the exit code with it.
	if result.Stdout != "out\n" || result.Stderr != "err\n" || result.ExitCode != 3 {
		t.Fatalf("the three streams must stay apart: %+v", result)
	}
}

func TestProbeRejectsAnUnknownName(t *testing.T) {
	_, _, err := answerProbe(t, "demo", "echoo", false)
	if err == nil || !strings.Contains(err.Error(), `check "demo" has no probe "echoo"`) {
		t.Fatalf("a mistyped probe names the check it looked in: %v", err)
	}
	if !strings.Contains(err.Error(), "echo") {
		t.Fatalf("a mistyped probe suggests the close one: %v", err)
	}

	_, _, err = answerProbe(t, "dmeo", "echo", false)
	if err == nil || !strings.Contains(err.Error(), `unknown check "dmeo"`) {
		t.Fatalf("a mistyped check is named: %v", err)
	}
}

// The mode is registered under local, and its own words are what it counts.
func TestProbeModeIsReachableFromTheLocalCommand(t *testing.T) {
	for _, args := range [][]string{{"local", "probe"}, {"local", "probe", "demo"}} {
		root := newRootCmd("test")
		root.SetArgs(args)
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		err := root.Execute()
		if err == nil || !strings.Contains(err.Error(), "probe needs a check and a probe") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}
