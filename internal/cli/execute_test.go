// The run's own damage boundary: a panic on the command's path, outside any
// check's walk, becomes one message and karma's exit code — where nothing above
// Execute recovers, so the alternative is a Go stack trace, the report written so
// far lost, and the status a failed connection uses.

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
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
	dir := t.TempDir()
	err := Execute(context.Background(), explodingWriter{}, io.Discard, session.LocalTransport{},
		model.RunOptions{Timeout: time.Second, SaveDir: dir}, nil)
	var coded exitError
	if !errors.As(err, &coded) {
		t.Fatalf("a damaged run should come back as a coded error, got %v", err)
	}
	if coded.code != ExitInternal {
		t.Fatalf("damage is karma's own exit code (%d), got %d", ExitInternal, coded.code)
	}
	record, readErr := os.ReadFile(filepath.Join(dir, crashName))
	if readErr != nil {
		t.Fatalf("the bundle should keep the account of what broke: %v", readErr)
	}
	for _, want := range []string{"collection", "the report writer blew up"} {
		if !strings.Contains(string(record), want) {
			t.Fatalf("the record should name %q:\n%s", want, record)
		}
	}
}
