// Evidence saving: each check's raw text is written into the --save directory as
// <aspect>/<check id>.txt. Only checks with a body are written; a repeated run
// overwrites files of the same name.

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
	if result.Output != "" {
		s.write(check, result.Output)
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
