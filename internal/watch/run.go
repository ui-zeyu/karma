package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"karma/internal/fault"
)

// Run reads one source and writes each event as a line. A JSON run writes one
// object per line instead; the source line the caller prints to stderr stays
// out of the stream.
func Run(ctx context.Context, out io.Writer, src Source, opt Options) error {
	return RunWith(ctx, out, src, opt, NewAnnotator())
}

// RunWith is Run with the annotator chosen by the caller; nil leaves events
// exactly as the source stated them, which is what the tests read.
func RunWith(ctx context.Context, out io.Writer, src Source, opt Options, annotator *Annotator) error {
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

	encoder := json.NewEncoder(out)
	for event := range events {
		if annotator != nil {
			annotator.Annotate(&event)
		}
		var err error
		if opt.JSON {
			err = encoder.Encode(event)
		} else {
			_, err = fmt.Fprintln(out, Line(event))
		}
		if err != nil {
			cancel()
			return err
		}
	}
	return <-errs
}
