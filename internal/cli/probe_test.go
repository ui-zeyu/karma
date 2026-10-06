package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"karma/internal/define"
	"karma/internal/model"
)

// probeCatalog is a stand-in catalog: one check per shape a caller has to read
// back. A Command runs wherever the test does; a Dual with only a script side is
// a tier the local channel does not carry; a body that refuses is the tier's own
// report that it cannot run here.
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

// answerProbe runs one probe and returns what a caller reads back: the two
// streams and the process status that carries the verdict.
func answerProbe(t *testing.T, check, label string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := runProbe(context.Background(), &stdout, &stderr, probeCatalog(), check, label)
	if err == nil {
		t.Fatal("the mode ends every answer with a status")
	}
	var silent silentError
	if !errors.As(err, &silent) {
		t.Fatalf("an answered probe reports only its status, got %v", err)
	}
	return stdout.String(), stderr.String(), int(silent.code)
}

func TestProbeHandsBackTheTierStreamsAndStatus(t *testing.T) {
	out, warn, code := answerProbe(t, "demo", "echo")
	if out != "hello\n" || warn != "" || code != 0 {
		t.Fatalf("an answered tier: stdout %q, stderr %q, status %d", out, warn, code)
	}
}

// A tier that printed while exiting non-zero is an answer, exit code and all; one
// that exited non-zero with nothing on stdout is a failure. The distinction is
// the whole fallback chain's contract, so the status has to carry it.
func TestProbeSaysAnsweredAndFailedAsTheChainReadsThem(t *testing.T) {
	out, warn, code := answerProbe(t, "demo", "noisy")
	if out != "out\n" || warn != "err\n" || code != 3 {
		t.Fatalf("a non-zero exit with stdout is an answer that keeps its status: %q / %q / %d", out, warn, code)
	}

	out, warn, code = answerProbe(t, "demo", "silent")
	if out != "" || warn != "why\n" || code != 9 {
		t.Fatalf("a non-zero exit with nothing on stdout is a failure: %q / %q / %d", out, warn, code)
	}
}

// A tier the local channel does not carry answers the 127 a missing binary gives,
// with an empty body: that is what the caller's walk reads to try the next tier.
func TestProbeAnswersUnavailableForATierThisChannelLacks(t *testing.T) {
	out, _, code := answerProbe(t, "demo", "script-only")
	if out != "" || code != 127 {
		t.Fatalf("a missing tier reads as an empty body and 127: %q / %d", out, code)
	}
}

func TestProbeAnswersUnavailableForABodyThatCannotRunHere(t *testing.T) {
	out, warn, code := answerProbe(t, "demo", "unavailable")
	if out != "" || code != 127 {
		t.Fatalf("a body that cannot run here is unavailable too: %q / %d", out, code)
	}
	if !strings.Contains(warn, "unavailable") {
		t.Fatalf("the tier's own reason travels on stderr: %q", warn)
	}
}

func TestProbeAnswersFailedForABodyThatBroke(t *testing.T) {
	out, warn, code := answerProbe(t, "demo", "broken")
	if out != "" || code != 1 || !strings.Contains(warn, "gave up") {
		t.Fatalf("a body that gave up is a failed tier that names why: %q / %q / %d", out, warn, code)
	}
}

// The status is the verdict's, and it is what a channel's verdictFor reads back:
// these two lines are that function's arms, spelled as the results it must get.
func TestExitForProbeSpeaksVerdictFor(t *testing.T) {
	for _, tc := range []struct {
		verdict  model.Verdict
		exitCode int
		want     int
	}{
		{model.VerdictAnswered, 0, 0},
		{model.VerdictAnswered, 3, 3},
		{model.VerdictAnswered, -1, 0},
		{model.VerdictUnavailable, 127, 127},
		{model.VerdictUnavailable, -1, 127},
		{model.VerdictFailed, 9, 9},
		{model.VerdictFailed, 0, 1},
		{model.VerdictFailed, -1, 1},
		{model.VerdictTimedOut, -1, 1},
		{model.VerdictInterrupted, -1, 1},
	} {
		if got := exitForProbe(tc.verdict, tc.exitCode); got != tc.want {
			t.Fatalf("%v (%d) said as a status: %d, want %d", tc.verdict, tc.exitCode, got, tc.want)
		}
	}
}

func TestProbeRejectsAnUnknownName(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runProbe(context.Background(), &stdout, &stderr, probeCatalog(), "demo", "echoo")
	if err == nil || !strings.Contains(err.Error(), `check "demo" has no probe "echoo"`) {
		t.Fatalf("a mistyped probe names the check it looked in: %v", err)
	}
	if !strings.Contains(err.Error(), "echo") {
		t.Fatalf("a mistyped probe suggests the close one: %v", err)
	}
	var silent silentError
	if errors.As(err, &silent) {
		t.Fatal("a mistake is a message, not a status the caller reads as a verdict")
	}

	err = runProbe(context.Background(), &stdout, &stderr, probeCatalog(), "dmeo", "echo")
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
