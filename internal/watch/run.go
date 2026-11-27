package watch

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"karma/internal/fault"
)

// annotateWorkers is the pipeline's annotation width. Four annotators keep a
// burst of exec events moving while all of them share the sharded path cache;
// the reordering below puts their output back into the source's order.
const annotateWorkers = 4

// Run reads one source and writes each event as a line. A JSON run writes one
// object per line instead; the source line the caller prints to stderr stays
// out of the stream.
func Run(ctx context.Context, out io.Writer, src Source, opt RunOptions) error {
	return RunWith(ctx, out, src, opt, NewAnnotator(ctx))
}

// RunWith is Run with the annotator chosen by the caller. The source's own
// failure is part of the answer: a subscription the kernel refused must not
// end as a silent exit 0, so the error is read back once the stream has
// ended and the source has stopped.
func RunWith(ctx context.Context, out io.Writer, src Source, opt RunOptions, annotator *Annotator) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	events := make(chan Event, 256)
	errs := make(chan error, 1)
	go func() {
		err := fault.Catch("watch "+src.Name(), func() error {
			return src.Run(ctx, events)
		})
		close(events)
		errs <- err
	}()

	// The stream is one event per line, so the writes are buffered and
	// flushed once the source has stopped; a flush failure joins the answer.
	buffered := bufio.NewWriter(out)
	err := runPipeline(ctx, buffered, opt, events, annotator)
	cancel()
	return errors.Join(err, buffered.Flush(), <-errs)
}

// noImageNotice is how many no-image exec events pass before the text stream
// says so. One is normal — a shell fork that dies in the /proc read; a
// stream of them is the shape of a dropper, and the count names it without
// judging any single event.
const noImageNotice = 10

// writeEvents is the passthrough the tests read: every event, in order, as
// the source stated them. In text mode it also keeps the no-image count, so
// the recall the empty-image guard spends is visible as a rate.
func writeEvents(out io.Writer, opt RunOptions, events <-chan Event) error {
	encoder := json.NewEncoder(out)
	noImage := 0
	for event := range events {
		if event.Proc != nil && event.Proc.Kind == KindExec && event.Proc.Exe == "" {
			noImage++
			if !opt.JSON && noImage%noImageNotice == 0 {
				fmt.Fprintf(out, "watch: %d exec events carried no image (the process was gone before /proc answered); grep flags=no-image for them\n", noImage)
			}
		}
		if err := emit(out, opt, encoder, event); err != nil {
			return err
		}
	}
	return nil
}

// filled is one event a worker finished, with its place in the source's
// order.
type filled struct {
	seq   uint64
	event Event
}

// runPipeline annotates events through a bounded worker pool and hands the
// writer its events back in the order the source produced them: the pipeline
// never trades throughput for a scrambled stream.
func runPipeline(ctx context.Context, out io.Writer, opt RunOptions, events <-chan Event, annotator *Annotator) error {
	jobs := make(chan Event, 256)
	go func() {
		defer close(jobs)
		seq := uint64(1)
		for event := range events {
			event.Seq = seq
			seq++
			if !deliver(ctx, jobs, event) {
				return
			}
		}
	}()

	done := make(chan filled, 256)
	var workers sync.WaitGroup
	for index := 0; index < annotateWorkers; index++ {
		workers.Add(1)
		go func(own *Annotator) {
			defer workers.Done()
			for event := range jobs {
				own.Annotate(&event)
				if !deliver(ctx, done, filled{seq: event.Seq, event: event}) {
					return
				}
			}
		}(annotator.share())
	}
	go func() {
		workers.Wait()
		close(done)
	}()

	return writeEvents(out, opt, reorder(ctx, done))
}

// reorder restores the source's order: one slot per sequence number, released
// to the writer in sequence.
func reorder(ctx context.Context, done <-chan filled) <-chan Event {
	ordered := make(chan Event, 256)
	go func() {
		defer close(ordered)
		expect := uint64(1)
		pending := map[uint64]Event{}
		for slot := range done {
			pending[slot.seq] = slot.event
			for {
				event, ok := pending[expect]
				if !ok {
					break
				}
				delete(pending, expect)
				expect++
				if !deliver(ctx, ordered, event) {
					return
				}
			}
		}
	}()
	return ordered
}

// deliver sends one item, stopping when the context ends so a stopped reader
// never leaves the pipeline or a source blocked on a full channel.
func deliver[T any](ctx context.Context, out chan<- T, value T) bool {
	select {
	case out <- value:
		return true
	case <-ctx.Done():
		return false
	}
}

func emit(out io.Writer, opt RunOptions, encoder *json.Encoder, event Event) error {
	if opt.JSON {
		return encoder.Encode(event)
	}
	_, err := io.WriteString(out, Line(event)+"\n")
	return err
}
