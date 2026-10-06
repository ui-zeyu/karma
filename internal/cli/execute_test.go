// The run's own damage boundary: a panic on the command's path, outside any
// check's walk, becomes one message and karma's exit code — where nothing above
// Execute recovers, so the alternative is a Go stack trace, the report written so
// far lost, and the status a failed connection uses.

package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"karma/internal/model"
	"karma/internal/session"
)

// explodingWriter panics on the first write: any panic on the command's own path
// (the header, fact rendering, the presentation setup) looks like this.
type explodingWriter struct{}

func (explodingWriter) Write([]byte) (int, error) { panic("the report writer blew up") }

func TestExecuteTurnsDamageIntoAReportedRun(t *testing.T) {
	err := Execute(context.Background(), explodingWriter{}, io.Discard, session.LocalTransport{},
		model.RunOptions{Timeout: time.Second}, nil)
	var coded exitError
	if !errors.As(err, &coded) {
		t.Fatalf("a damaged run should come back as a coded error, got %v", err)
	}
	if coded.code != ExitInternal {
		t.Fatalf("damage is karma's own exit code (%d), got %d", ExitInternal, coded.code)
	}
	// The message is the whole account of what broke: it names the boundary, and
	// the panic's own text travels with it.
	for _, want := range []string{"collection", "the report writer blew up"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the message should name %q: %v", want, err)
		}
	}
}
