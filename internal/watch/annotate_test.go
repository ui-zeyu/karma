package watch

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExecWithoutAnImageCarriesNoVerdict pins the guard that keeps a judgment
// off an event whose image the source could not read: the connector fires at
// exec and the process can be gone before /proc answers. Judging empty facts
// would print origin=unknown, a finding-shaped answer to a read that never
// happened.
func TestExecWithoutAnImageCarriesNoVerdict(t *testing.T) {
	annotator := NewAnnotatorWith(nil)
	event := Event{
		Source: SourceConnector,
		Proc:   &Proc{Kind: KindExec, PID: 42, UID: 0, Comm: "shortlived"},
	}
	annotator.Annotate(&event)
	if event.Verdict != nil {
		t.Errorf("an exec without an image carries a verdict: %+v", event.Verdict)
	}
	if !hasFlag(event.Flags, FlagNoImage) {
		t.Errorf("flags = %v, want no-image so the event stays greppable", event.Flags)
	}
}

func TestExitAndForkCarryNoVerdict(t *testing.T) {
	annotator := NewAnnotatorWith(nil)
	for kind, pid := range map[Kind]int{KindExit: 7, KindFork: 8} {
		event := Event{
			Source: SourcePoll,
			Proc:   &Proc{Kind: kind, PID: pid, UID: 0, Exe: "/usr/bin/true"},
		}
		annotator.Annotate(&event)
		if event.Verdict != nil {
			t.Errorf("a %s event carries a verdict: %+v", kind, event.Verdict)
		}
	}
}

func TestAnnotateFlagsFactsNotNames(t *testing.T) {
	// A deleted image: the file existed, the suffix says it is unlinked now.
	ghost := filepath.Join(t.TempDir(), "gone")
	event := Event{
		Source: SourcePoll,
		Proc:   &Proc{Kind: KindExec, PID: 9, UID: 0, Exe: ghost + " (deleted)"},
	}
	NewAnnotatorWith(nil).Annotate(&event)
	if event.Proc.Exe != ghost {
		t.Errorf("the deleted suffix stayed on the exe: %q", event.Proc.Exe)
	}
	if !hasFlag(event.Flags, FlagDeleted) {
		t.Errorf("flags = %v, want deleted", event.Flags)
	}
	// An administrator-layer working directory is a fact of its own.
	event = Event{
		Source: SourcePoll,
		Proc:   &Proc{Kind: KindExec, PID: 9, UID: 0, Exe: ghost + " (deleted)", Cwd: "/etc/profile.d"},
	}
	NewAnnotatorWith(nil).Annotate(&event)
	if !hasFlag(event.Flags, FlagAdminCwd) {
		t.Errorf("flags = %v, want admin-cwd", event.Flags)
	}
}

func TestAnnotateCarriesTheInterpreterScript(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "payload.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	event := Event{
		Source: SourcePoll,
		Proc: &Proc{Kind: KindExec, PID: 9, UID: os.Getuid(), Exe: "/bin/sh",
			Cmdline: "sh " + script, Cwd: dir},
	}
	NewAnnotatorWith(nil).Annotate(&event)
	if event.Proc.Script != script {
		t.Errorf("script = %q, want %q", event.Proc.Script, script)
	}
	if event.Verdict == nil {
		t.Fatal("an exec with an image carries no verdict")
	}
	// The judgment reads the weaker of the image and the script; the script's
	// own facts stand beside the verdict.
	if strings.Contains(event.Proc.Cmdline, "payload.sh") && event.Verdict.Severity.String() == "" {
		t.Errorf("verdict without a severity: %+v", event.Verdict)
	}
}

func TestFlagsPrintInTheTableOrder(t *testing.T) {
	set := newFlagSet(nil)
	set.add(FlagWritable)
	set.add(FlagDeleted)
	set.add(FlagAdminScript)
	set.add(FlagUnowned)
	got := set.sorted()
	want := []Flag{FlagDeleted, FlagUnowned, FlagWritable, FlagAdminScript}
	if len(got) != len(want) {
		t.Fatalf("flags = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("flag %d = %s, want %s", index, got[index], want[index])
		}
	}
}

// TestReorderRestoresTheSourceOrder feeds the reorder stage a scrambled burst
// and reads it back in sequence order.
func TestReorderRestoresTheSourceOrder(t *testing.T) {
	done := make(chan filled, 8)
	events := []Event{
		{Seq: 3, Proc: &Proc{PID: 3}},
		{Seq: 1, Proc: &Proc{PID: 1}},
		{Seq: 2, Proc: &Proc{PID: 2}},
	}
	for _, event := range events {
		done <- filled{seq: event.Seq, event: event}
	}
	close(done)
	ordered := reorder(context.Background(), done)
	var pids []int
	for event := range ordered {
		pids = append(pids, event.Proc.PID)
	}
	if len(pids) != 3 || pids[0] != 1 || pids[1] != 2 || pids[2] != 3 {
		t.Errorf("order = %v, want 1 2 3", pids)
	}
}

func hasFlag(flags []Flag, want Flag) bool {
	for _, flag := range flags {
		if flag == want {
			return true
		}
	}
	return false
}
