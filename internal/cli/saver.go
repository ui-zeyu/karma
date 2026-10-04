// Evidence saving: each check's raw output is written into the --save directory as
// <aspect>/<check id>.txt. The text is the channel's stdout exactly as collected —
// before the reading layer's byte cap, section split, and normalization — so the
// files are the evidence, not the presentation. Only checks that collected output
// are written; a repeated run overwrites files of the same name.

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"karma/internal/model"
	"karma/internal/runner"
)

type saveObserver struct {
	dir  string
	mu   sync.Mutex
	next runner.Observer
}

// CheckStarted passes the progress through.
func (s *saveObserver) CheckStarted(check *model.Check) { s.next.CheckStarted(check) }

// CheckFinished saves first and passes through after; a failed write is reported
// on stderr and does not block presentation.
func (s *saveObserver) CheckFinished(check *model.Check, result *model.CheckResult) {
	if result.Raw != "" {
		s.write(check, result.Raw)
	}
	s.next.CheckFinished(check, result)
}

func (s *saveObserver) write(check *model.Check, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Join(s.dir, string(check.Aspect))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "save failed: "+err.Error())
		return
	}
	path := filepath.Join(dir, check.ID+".txt")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "save failed: "+err.Error())
	}
}
