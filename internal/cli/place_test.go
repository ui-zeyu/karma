// Placement's own pieces: the order a collector is looked for and put in, the
// md5 that decides whether a copy found on the target may be run, and the
// fallbacks when a directory will not take one.

package cli

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/session"
)

// placedSession is a target with a small file system: it answers uname, the
// account's home, the hash of a file that is there, and records what it was
// asked to do. The packer probe answers "none", so the program travels whole and
// the test can hash exactly what was uploaded.
type placedSession struct {
	files   map[string]string // path -> md5, the files that are already there
	refuse  map[string]bool   // directories whose preparation fails
	noHash  bool              // the target has no md5sum (busybox's either)
	ran     []string
	uploads []string
}

func newPlacedSession() *placedSession {
	return &placedSession{files: map[string]string{}, refuse: map[string]bool{}}
}

func (s *placedSession) Name() string           { return "placed" }
func (s *placedSession) Channel() model.Channel { return model.ChanSSH }
func (s *placedSession) Describe() string       { return "ssh ops@target" }
func (s *placedSession) Close() error           { return nil }

func (s *placedSession) Run(_ context.Context, call model.Call) model.RunResult {
	command := session.RenderShell(call.Inv)
	s.ran = append(s.ran, command)
	switch {
	case strings.Contains(command, "uname -s -m"):
		return answered(unameOfThisBuild())
	case strings.Contains(command, "$HOME"):
		return answered("/home/ops")
	case strings.Contains(command, "command -v gzip"):
		return answered("none")
	case strings.Contains(command, "md5sum"):
		// The hash question names one file: answer for the one that is there.
		if s.noHash {
			return model.RunResult{Verdict: model.VerdictFailed, ExitCode: 1}
		}
		for path, sum := range s.files {
			if strings.Contains(command, path) {
				return answered(sum)
			}
		}
		return model.RunResult{Verdict: model.VerdictUnavailable, ExitCode: 127}
	case strings.Contains(command, "mkdir -m 700"):
		for dir := range s.refuse {
			if strings.Contains(command, dir) {
				return model.RunResult{Verdict: model.VerdictFailed, Stderr: "mkdir: Permission denied", ExitCode: 1}
			}
		}
		return answered("")
	case strings.Contains(command, "version"):
		return answered("karma " + buildVersion)
	}
	return answered("")
}

func (s *placedSession) Upload(_ context.Context, path string, content []byte) error {
	s.uploads = append(s.uploads, path)
	sum := md5.Sum(content)
	s.files[path] = hex.EncodeToString(sum[:])
	return nil
}

func answered(stdout string) model.RunResult {
	if stdout != "" {
		stdout += "\n"
	}
	return model.RunResult{Verdict: model.VerdictAnswered, Stdout: stdout}
}

// unameOfThisBuild spells this build's platform the way the target's uname
// would, so a placement here reads the program as this binary.
func unameOfThisBuild() string {
	system := map[string]string{"linux": "Linux", "darwin": "Darwin"}[runtime.GOOS]
	machine := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	if system == "" || machine == "" {
		panic("this test build is a platform the test does not spell")
	}
	return system + " " + machine
}

// thisBuildDigest is the hash of the program a placement would ship to a target
// of this platform: the test binary itself, since this build is that platform.
func thisBuildDigest(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(content)
	return hex.EncodeToString(sum[:])
}

func TestCollectorDirsOrdersTheOperatorsWordsFirst(t *testing.T) {
	lookup, place := collectorDirs("/home/ops", placeOptions{})
	if len(lookup) != 2 || lookup[0] != "/home/ops/.karma" || lookup[1] != "/tmp/karma" {
		t.Fatalf("the default order = %v", lookup)
	}
	if len(place) != 2 || place[0] != lookup[0] {
		t.Fatalf("placement follows the same order: %v", place)
	}

	// --find leads the lookup and leaves the placement to the default order: a
	// miss still puts a copy where the account's own directory is.
	lookup, place = collectorDirs("/home/ops", placeOptions{find: "/opt/tools"})
	if len(lookup) != 3 || lookup[0] != "/opt/tools" || lookup[1] != "/home/ops/.karma" {
		t.Fatalf("--find leads the lookup: %v", lookup)
	}
	if len(place) != 2 || place[0] != "/home/ops/.karma" {
		t.Fatalf("--find does not move the placement: %v", place)
	}

	// --place pins both: the operator said where the collector lives, so nothing
	// else is looked at and nowhere else is written.
	lookup, place = collectorDirs("/home/ops", placeOptions{place: "/srv/k"})
	if len(lookup) != 1 || lookup[0] != "/srv/k" {
		t.Fatalf("--place pins the lookup: %v", lookup)
	}
	if len(place) != 1 || place[0] != "/srv/k" {
		t.Fatalf("--place pins the placement: %v", place)
	}

	// An account with no home directory has one candidate fewer, not a guess.
	lookup, _ = collectorDirs("", placeOptions{})
	if len(lookup) != 1 || lookup[0] != "/tmp/karma" {
		t.Fatalf("a target with no home = %v", lookup)
	}
}

// A copy that is already there, and whose bytes are this binary's, is reused:
// nothing travels and the path is the one that was found.
func TestPlacementReusesACopyThatMatchesThisBuild(t *testing.T) {
	sess := newPlacedSession()
	sess.files["/home/ops/.karma/karma"] = thisBuildDigest(t)

	path, reused, err := placeCollector(context.Background(), sess, placeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/home/ops/.karma/karma" || !reused {
		t.Fatalf("placeCollector = %q, %v", path, reused)
	}
	if len(sess.uploads) != 0 {
		t.Fatalf("a reused copy travels nothing: %v", sess.uploads)
	}
}

// A copy that is there but is not this build is replaced rather than run: the
// hash is the check that does not execute the file.
func TestPlacementReplacesACopyThatIsNotThisBuild(t *testing.T) {
	sess := newPlacedSession()
	sess.files["/home/ops/.karma/karma"] = strings.Repeat("0", 32)

	path, reused, err := placeCollector(context.Background(), sess, placeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/home/ops/.karma/karma" || reused {
		t.Fatalf("a stale copy should be replaced in place: %q, %v", path, reused)
	}
	if len(sess.uploads) != 1 || sess.uploads[0] != path {
		t.Fatalf("the fresh copy lands at the found path: %v", sess.uploads)
	}
}

// On a target with no hash tool nothing can be verified, so nothing is reused:
// the upload's own checks are what prove the copy.
func TestPlacementDoesNotReuseWhatItCannotHash(t *testing.T) {
	sess := newPlacedSession()
	sess.files["/home/ops/.karma/karma"] = thisBuildDigest(t)
	sess.noHash = true

	path, reused, err := placeCollector(context.Background(), sess, placeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if reused || path != "/home/ops/.karma/karma" {
		t.Fatalf("an unverifiable copy is replaced: %q, %v", path, reused)
	}
	if len(sess.uploads) != 1 {
		t.Fatalf("the replacement should have been uploaded: %v", sess.uploads)
	}
}

func TestPlacementPutsTheFirstWorkingDirectoryToUse(t *testing.T) {
	sess := newPlacedSession()
	path, reused, err := placeCollector(context.Background(), sess, placeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if reused || path != "/home/ops/.karma/karma" {
		t.Fatalf("the account's own directory comes first: %q, %v", path, reused)
	}
	if !sess.refuse["/tmp/karma"] {
		// The home directory answered, so /tmp was never tried.
		if len(sess.uploads) != 1 {
			t.Fatalf("one upload, got %v", sess.uploads)
		}
	}
}

// A directory that will not take the file falls through to the next, with the
// target's own words for the one that refused.
func TestPlacementFallsThroughToTmp(t *testing.T) {
	sess := newPlacedSession()
	sess.refuse["/home/ops/.karma"] = true

	path, reused, err := placeCollector(context.Background(), sess, placeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if reused || path != "/tmp/karma/karma" {
		t.Fatalf("the next candidate should take it: %q, %v", path, reused)
	}
}

// Every candidate refusing is one message naming each one and the way out: a
// host karma cannot be placed on is collected by running karma on it.
func TestPlacementReportsEveryDirectoryThatRefused(t *testing.T) {
	sess := newPlacedSession()
	sess.refuse["/home/ops/.karma"] = true
	sess.refuse["/tmp/karma"] = true

	_, _, err := placeCollector(context.Background(), sess, placeOptions{})
	if err == nil {
		t.Fatal("a target that took nothing was accepted")
	}
	for _, want := range []string{"/home/ops/.karma", "/tmp/karma", "Permission denied", "running karma on it"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the message should carry %q: %v", want, err)
		}
	}
}

// The operator's words replace the order: --find names where to look, --place
// where to put a copy.
func TestPlacementHonorsFindAndPlace(t *testing.T) {
	sess := newPlacedSession()
	sess.files["/opt/tools/karma"] = thisBuildDigest(t)
	path, reused, err := placeCollector(context.Background(), sess, placeOptions{find: "/opt/tools"})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/opt/tools/karma" || !reused {
		t.Fatalf("--find should be looked in first: %q, %v", path, reused)
	}

	sess = newPlacedSession()
	path, _, err = placeCollector(context.Background(), sess, placeOptions{place: "/srv/k"})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/srv/k/karma" || len(sess.uploads) != 1 || sess.uploads[0] != "/srv/k/karma" {
		t.Fatalf("--place should be written to: %q, %v", path, sess.uploads)
	}
}

// The two flags are read from the command line the modes share.
func TestPlaceOptionsComeFromTheFlags(t *testing.T) {
	cmd := newSSHCmd()
	if err := cmd.Flags().Set("find", "/opt/tools"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("place", "/srv/k"); err != nil {
		t.Fatal(err)
	}
	opts := placeOptionsFrom(cmd.Flags())
	if opts.find != "/opt/tools" || opts.place != "/srv/k" {
		t.Fatalf("placeOptions = %+v", opts)
	}
	// A command line that never registered them reads the default order.
	if got := placeOptionsFrom(newLocalCmd().Flags()); got.find != "" || got.place != "" {
		t.Fatalf("the local channel places nothing: %+v", got)
	}
}

// The directory a collector lands in is the collector's own, and a name that is
// already a link is not a place to write through.
func TestPrepareDirRefusesASymlinkAndSetsTheMode(t *testing.T) {
	command := prepareDirCommand("/tmp/karma")
	for _, want := range []string{`[ -L "$d" ] && exit 1`, `mkdir -m 700 -p "$d"`} {
		if !strings.Contains(command, want) {
			t.Fatalf("the command should carry %q: %s", want, command)
		}
	}
}

// The hash is asked with whichever tool the target has, and a file that is not
// executable there is not a candidate at all.
func TestHashCommandGuardsOnTheToolsAndOnTheFile(t *testing.T) {
	command := hashCommand("/home/ops/.karma/karma")
	for _, want := range []string{`[ -x "$p" ] || exit 127`, "command -v md5sum", "command -v md5"} {
		if !strings.Contains(command, want) {
			t.Fatalf("the command should carry %q: %s", want, command)
		}
	}
	if !bytes.Contains([]byte(command), []byte("/home/ops/.karma/karma")) {
		t.Fatalf("the command should name the file: %s", command)
	}
}
