// Evidence saving: each check's raw output is written into the --save directory
// as <aspect>/<check id>.txt. The text is the channel's stdout exactly as
// collected — before the reading layer's byte cap, section split, and
// normalization — so the files are the evidence, not the presentation. Only
// checks that collected output are written; a repeated run overwrites files of
// the same name.
//
// manifest.json records the run's provenance — karma version, channel, host
// facts, UTC start time — and one entry per file with its size and sha256, so
// a bundle can be identified and checked for tampering without opening the
// files.

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"karma/internal/fault"
	"karma/internal/model"
	"karma/internal/runner"
)

// manifestFile is one evidence file's entry in manifest.json. Path is
// slash-joined relative to the save directory.
type manifestFile struct {
	Path   string `json:"path"`
	Check  string `json:"check"`
	Aspect string `json:"aspect"`
	Probe  string `json:"probe"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// manifest is --save's manifest.json: the run's provenance plus one entry per
// evidence file.
type manifest struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Channel  string         `json:"channel"`
	Hostname string         `json:"hostname"`
	OS       string         `json:"os"`
	Kernel   string         `json:"kernel"`
	UID      int            `json:"uid"`
	User     string         `json:"user,omitempty"`
	Started  time.Time      `json:"started"`
	Files    []manifestFile `json:"files"`
}

type saveObserver struct {
	dir    string
	record manifest
	mu     sync.Mutex
	next   runner.Observer
}

// newSaveObserver freezes the run's provenance at construction time, so the
// manifest describes exactly the run that wrote the files.
func newSaveObserver(dir, version, channel string, facts model.HostFacts, next runner.Observer) *saveObserver {
	return &saveObserver{
		dir: dir,
		record: manifest{
			Tool:     "karma",
			Version:  version,
			Channel:  channel,
			Hostname: facts.Hostname,
			OS:       facts.OsPretty,
			Kernel:   facts.Kernel,
			UID:      facts.UID,
			User:     facts.User,
			Started:  time.Now().UTC(),
		},
		next: next,
	}
}

// CheckStarted passes the progress through.
func (s *saveObserver) CheckStarted(check *model.Check) { s.next.CheckStarted(check) }

// CheckFinished saves first and passes through after; a failed write is reported
// on stderr and does not block presentation.
func (s *saveObserver) CheckFinished(check *model.Check, result *model.CheckResult) {
	if result.Raw != "" {
		s.write(check, result)
	}
	s.next.CheckFinished(check, result)
}

// Damaged passes a piece of presentation the run could not show on to the
// observer that owns the report stream.
func (s *saveObserver) Damaged(check *model.Check, err error) { s.next.Damaged(check, err) }

// crashName is the record a damaged run leaves in the bundle: the message names
// the boundary that broke and the file carries the stack, which is what makes an
// internal error actionable after the fact.
const crashName = "_karma-internal-error.txt"

// saveCrash writes one internal error beside the evidence. A run without --save
// has nowhere to put it, and the command line's message is then the whole
// account.
func saveCrash(dir string, crash *fault.Panic) {
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "save failed: "+err.Error())
		return
	}
	if err := os.WriteFile(filepath.Join(dir, crashName), []byte(crash.Detail()), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "save failed: "+err.Error())
	}
}

// finalize writes manifest.json after the run's checks are done, so the
// manifest lists exactly the files this run wrote.
func (s *saveObserver) finalize() {
	if err := s.writeManifest(); err != nil {
		fmt.Fprintln(os.Stderr, "save failed: "+err.Error())
	}
}

func (s *saveObserver) write(check *model.Check, result *model.CheckResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	aspect := string(check.Aspect)
	dir := filepath.Join(s.dir, aspect)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "save failed: "+err.Error())
		return
	}
	name := check.ID + ".txt"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(result.Raw), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "save failed: "+err.Error())
		return
	}
	sum := sha256.Sum256([]byte(result.Raw))
	s.record.Files = append(s.record.Files, manifestFile{
		Path:   aspect + "/" + name,
		Check:  check.ID,
		Aspect: aspect,
		Probe:  result.ProbeLabel,
		Bytes:  len(result.Raw),
		SHA256: hex.EncodeToString(sum[:]),
	})
}

func (s *saveObserver) writeManifest() error {
	s.mu.Lock()
	data, err := json.MarshalIndent(s.record, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "manifest.json"), data, 0o600)
}
