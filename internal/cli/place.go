// Placing the collector: where this binary may live on a target, how a copy that
// is already there is proved to be this build, and how a copy is put there when
// there is none.
//
// The order is the account's own directory first — exec-able almost everywhere,
// out of the way of a /tmp cleanup, and the first place an operator looks — then
// /tmp, which is always writable and often mounted noexec. The operator's own
// words replace the order: --find names the directory to look in, --place the one
// to put a copy in.
//
// A copy is reused only when its md5 equals this binary's. The hash is the one
// check that does not execute the file, so a stale build, a truncated write or
// someone else's file is replaced by a fresh upload rather than run; on a target
// with no hash tool at all nothing is reused, and the upload's own verifications
// (the decompressor's checksum, then the version line) are what prove the copy.
// Nothing removes the file afterwards: the next run finds it and reuses it.

package cli

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"karma/internal/model"
	"karma/internal/script"
	"karma/internal/session"
)

// collectorName is the file's name under every candidate directory, so the same
// path is looked for and written.
const collectorName = "karma"

// placeOptions is the operator's own words about where a collector lives.
type placeOptions struct {
	find  string // the directory to look in; empty uses the default order
	place string // the directory to put a copy in; empty uses the default order
}

// placeOptionsFrom reads the two flags. A command line that never registered
// them reads the zero value, which is the default order.
func placeOptionsFrom(flags *pflag.FlagSet) placeOptions {
	return placeOptions{find: stringFlag(flags, "find"), place: stringFlag(flags, "place")}
}

// collectorDirs returns the order a collector is looked for in and the order it
// is placed in.
//
// --place pins both: the operator has said where the collector lives, so nothing
// else is looked at and nowhere else is written — a directory that will not take
// the file is an error naming that directory, not a quiet move to another one.
// --find is about looking: it leads the default order (the account's own
// directory, then /tmp), and a miss still places a copy where the default order
// says.
func collectorDirs(home string, opts placeOptions) (lookup, place []string) {
	defaults := make([]string, 0, 2)
	if home != "" {
		defaults = append(defaults, filepath.Join(home, ".karma"))
	}
	defaults = append(defaults, filepath.Join("/tmp", collectorName))
	if opts.place != "" {
		return []string{opts.place}, []string{opts.place}
	}
	if opts.find != "" && !slices.Contains(defaults, opts.find) {
		return append([]string{opts.find}, defaults...), defaults
	}
	return defaults, defaults
}

// placeCollector returns the path of a collector on the target, reusing the copy
// that is already there and putting one there when there is none. reused says
// which of the two happened, for the mode that reports it.
//
// The two halves are separate on purpose: every lookup candidate is tried before
// anything is written, so a target whose collector merely moved (a /tmp that was
// cleared, a home directory that changed) costs no transfer.
func placeCollector(ctx context.Context, sess session.Session, opts placeOptions) (path string, reused bool, err error) {
	goos, goarch, err := targetPlatform(ctx, sess)
	if err != nil {
		return "", false, err
	}
	program, err := programFor(exeDir(), goos, goarch)
	if err != nil {
		return "", false, err
	}
	digest := md5.Sum(program)
	lookup, place := collectorDirs(targetHome(ctx, sess), opts)
	for _, dir := range lookup {
		candidate := filepath.Join(dir, collectorName)
		if collectorReady(ctx, sess, candidate, digest) {
			return candidate, true, nil
		}
	}
	var failures []string
	for _, dir := range place {
		candidate := filepath.Join(dir, collectorName)
		if err := uploadCollector(ctx, sess, dir, candidate, program); err != nil {
			failures = append(failures, fmt.Sprintf("  %s: %s", dir, err))
			continue
		}
		return candidate, false, nil
	}
	return "", false, fmt.Errorf("no directory on the target took the collector:\n%s\n"+
		"a host karma cannot be placed on is collected by running karma on it itself", strings.Join(failures, "\n"))
}

// targetHome reads the account's home directory. The shell expands it, so karma
// never has to guess a target's layout. An empty answer drops that candidate
// rather than placing the binary in an unknown directory.
func targetHome(ctx context.Context, sess session.Session) string {
	return strings.TrimSpace(bootCall(ctx, sess, model.Shell{Script: `printf '%s\n' "$HOME"`}).Stdout)
}

// collectorReady reports whether the file at path is this build, ready to run.
// The hash is asked of the target and compared here, so the file is never
// executed before it is known: a target with no md5sum (or busybox's) answers
// nothing, and the copy is replaced instead.
func collectorReady(ctx context.Context, sess session.Session, path string, digest [md5.Size]byte) bool {
	result := bootCall(ctx, sess, model.Shell{Script: hashCommand(path)})
	if result.Verdict != model.VerdictAnswered {
		return false
	}
	fields := strings.Fields(result.Stdout)
	return len(fields) > 0 && strings.EqualFold(fields[0], hex.EncodeToString(digest[:]))
}

// hashCommand prints the file's md5 with whichever tool the target has. The
// guards are `command -v` rather than a preference, so a minimal system with
// busybox's applets answers the same way as one with coreutils.
func hashCommand(path string) string {
	return script.Lines(
		"p="+script.Quote(path),
		`[ -x "$p" ] || exit 127`,
		`if command -v md5sum >/dev/null 2>&1; then md5sum "$p"; exit 0; fi`,
		`if command -v md5 >/dev/null 2>&1; then md5 -q "$p"; exit 0; fi`,
		"exit 1",
	)
}

// uploadCollector writes the program into dir and proves the write: the
// directory is the collector's own (mode 700, never through a symlink), the
// transfer is unpacked by the target, and the version line then says the file is
// this build and runs.
func uploadCollector(ctx context.Context, sess session.Session, dir, path string, program []byte) error {
	uploader, ok := sess.(session.Uploader)
	if !ok {
		return fmt.Errorf("the %s channel cannot carry a binary upload", sess.Name())
	}
	if result := bootCall(ctx, sess, model.Shell{Script: prepareDirCommand(dir)}); result.Verdict != model.VerdictAnswered {
		return errors.New(commandFailure(result))
	}
	shipment, err := planTransfer(ctx, sess, path, program)
	if err != nil {
		return err
	}
	if err := uploader.Upload(ctx, shipment.path, shipment.body); err != nil {
		return fmt.Errorf("uploading %s: %w", path, err)
	}
	return unpackUpload(ctx, sess, path, shipment.unpack)
}

// prepareDirCommand creates the directory a collector goes into, mode 700, and
// refuses a symlink: a name that is already a link is not a place to write
// through, and the target user owns the directory a copy lands in.
func prepareDirCommand(dir string) string {
	return script.Lines(
		"d="+script.Quote(dir),
		`[ -L "$d" ] && exit 1`,
		`mkdir -m 700 -p "$d" || exit 1`,
	)
}

// exeDir is the directory this binary was started from: the artifacts a release
// puts beside it are what a target of another platform is served with.
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

// artifactName is the file a release writes for one platform, beside the native
// binary: `karma-linux-amd64`, and the .exe suffix on Windows.
func artifactName(goos, goarch string) string {
	name := "karma-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// programFor returns the bytes to place on a target of this platform: this
// binary itself when it is that build, and otherwise the artifact a release
// writes for it beside the binary (`dist/karma-linux-amd64` and its kind).
//
// A workstation is rarely the platform it collects from — an operator on macOS
// audits Linux hosts — so the artifact is the normal case rather than a
// fallback, and its absence is the one thing the message has to explain.
func programFor(dir, goos, goarch string) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot find this binary: %w", err)
	}
	if runtime.GOOS == goos && runtime.GOARCH == goarch {
		return readProgram(exe)
	}
	name := artifactName(goos, goarch)
	if dir != "" {
		if content, err := readProgram(filepath.Join(dir, name)); err == nil {
			return content, nil
		}
	}
	return nil, fmt.Errorf("the target is %s/%s and this karma is %s/%s: put a build for it beside this binary "+
		"(%s) or run that build instead", goos, goarch, runtime.GOOS, runtime.GOARCH, name)
}

// readProgram reads one candidate binary whole; a missing or unreadable one is
// the caller's to report.
func readProgram(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}
