package watch

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// failSource emits its events, then fails. It stands for a source whose
// backend refused or died after the stream started.
type failSource struct {
	events []Event
	err    error
}

func (f failSource) Name() string { return "fail" }
func (f failSource) Caps() Caps   { return Caps{Process: true} }
func (f failSource) Run(ctx context.Context, out chan<- Event) error {
	for _, event := range f.events {
		if !send(ctx, out, event) {
			return nil
		}
	}
	return f.err
}

// TestTextStreamCountsNoImageExecs pins the writer's rate notice: the text
// stream names a run of imageless exec events, the JSON stream stays
// machine-readable.
func TestTextStreamCountsNoImageExecs(t *testing.T) {
	annotator := NewAnnotatorWith(nil)
	stream := func() <-chan Event {
		events := make(chan Event, noImageNotice)
		for index := 0; index < noImageNotice; index++ {
			event := Event{Source: SourcePoll, Proc: &Proc{Kind: KindExec, PID: index + 1}}
			annotator.Annotate(&event)
			events <- event
		}
		close(events)
		return events
	}
	var out bytes.Buffer
	writeEvents(&out, Options{}, stream())
	if !strings.Contains(out.String(), "carried no image") {
		t.Errorf("the text notice is missing: %q", out.String())
	}
	out.Reset()
	writeEvents(&out, Options{JSON: true}, stream())
	if strings.Contains(out.String(), "carried no image") {
		t.Errorf("the JSON stream grew a notice line: %q", out.String())
	}
	if !strings.Contains(out.String(), `"no-image"`) {
		t.Errorf("the JSON stream lost the no-image flag: %q", out.String())
	}
}

// TestRunWithReturnsTheSourceError pins that the pipeline's answer includes
// the source's own failure. The regression: the source goroutine wrote its
// error into a channel nobody read, so a refused subscription or a dead
// backend ended as a silent exit 0.
func TestRunWithReturnsTheSourceError(t *testing.T) {
	boom := errors.New("subscription refused")
	src := failSource{
		events: []Event{{Source: SourcePoll, Proc: &Proc{Kind: KindExec, PID: 4242, Exe: "/bin/true"}}},
		err:    boom,
	}
	for name, annotator := range map[string]*Annotator{"passthrough": nil, "pipeline": NewAnnotatorWith(nil)} {
		var out bytes.Buffer
		err := RunWith(context.Background(), &out, src, Options{}, annotator)
		if !errors.Is(err, boom) {
			t.Errorf("%s: RunWith error = %v, want the source's failure", name, err)
		}
		if !strings.Contains(out.String(), "4242") {
			t.Errorf("%s: the events before the failure were lost: %q", name, out.String())
		}
	}
}
