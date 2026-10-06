// Bootstrap: run karma's own binary on the target. The uploaded program reads
// the kernel's interfaces in process — no shell, no coreutils and no libc in
// the path — which is what makes it usable where those cannot be trusted, and
// it is the only way an ssh or ttyd target gets the local channel's checks
// (userland rootkit detection among them).
//
// The transfer rides the channel itself: ssh streams the file over the
// session's stdin, ttyd types it into the terminal it already has. Nothing is
// left behind unless --keep says so.

package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"karma/internal/model"
	"karma/internal/script"
	"karma/internal/session"
)

// bootstrapTimeout bounds the small commands around the transfer — uname, the
// version probe, the cleanup. The target's own karma has its own per-command
// timeouts, so the run itself carries no deadline: a full local collection
// takes minutes, and only the interrupt stops it.
const bootstrapTimeout = 30 * time.Second

// runBootstrap ships this binary to the target over the channel and runs its
// local mode there, streaming the report back.
func runBootstrap(ctx context.Context, transport session.Transport, options model.RunOptions, selectors []string, keep bool) error {
	sess, err := transport.Open()
	if err != nil {
		return err
	}
	defer sess.Close()
	uploader, ok := sess.(session.Uploader)
	if !ok {
		return fmt.Errorf("the %s channel cannot carry a binary upload", sess.Name())
	}
	streamer, ok := sess.(session.Streamer)
	if !ok {
		return fmt.Errorf("the %s channel cannot stream a run", sess.Name())
	}
	if err := checkTargetPlatform(ctx, sess); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find this binary: %w", err)
	}
	content, err := os.ReadFile(exe)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", exe, err)
	}
	dir := "/tmp/karma-" + randomSuffix()
	remote := dir + "/karma"
	// The cleanup is armed before the upload: a transfer that dies halfway
	// still has to take the directory it created with it.
	defer cleanUp(ctx, sess, dir, keep)
	if err := uploader.Upload(ctx, remote, content); err != nil {
		return fmt.Errorf("uploading %s: %w", remote, err)
	}
	if err := verifyUpload(ctx, streamer, remote); err != nil {
		return err
	}
	return runRemote(ctx, streamer, remote, options, selectors)
}

// checkTargetPlatform compares the target's kernel and machine with this
// binary's build: a cross-arch run cannot happen, and the mistake belongs to
// this command rather than to a failed exec on the target.
func checkTargetPlatform(ctx context.Context, sess session.Session) error {
	result := sess.Run(ctx, model.Shell{Script: "uname -s -m"}, bootstrapTimeout, 0)
	fields := strings.Fields(result.Stdout)
	if len(fields) < 2 {
		return fmt.Errorf("cannot read the target's platform (uname said %q)", strings.TrimSpace(result.Stdout))
	}
	targetOS, targetArch, err := unamePlatform(fields[0], fields[1])
	if err != nil {
		return err
	}
	if targetOS != runtime.GOOS || targetArch != runtime.GOARCH {
		return fmt.Errorf("the target runs %s/%s and this karma is %s/%s; build for the target (GOOS=%s GOARCH=%s) and run that build",
			targetOS, targetArch, runtime.GOOS, runtime.GOARCH, targetOS, targetArch)
	}
	return nil
}

// verifyUpload runs `karma version` from the uploaded path: a truncated or
// undecodable transfer fails there instead of at the first check.
func verifyUpload(ctx context.Context, streamer session.Streamer, remote string) error {
	var out, errOut strings.Builder
	code, err := streamer.Stream(ctx, model.Shell{Script: script.Join([]string{remote, "version"})}, &out, &errOut)
	if err != nil {
		return fmt.Errorf("running the uploaded binary: %w", err)
	}
	want := "karma " + buildVersion
	if got := strings.TrimSpace(out.String()); got != want {
		return fmt.Errorf("the uploaded binary answered %q (exit %d), want %q: %s",
			got, code, want, strings.TrimSpace(errOut.String()))
	}
	return nil
}

// runRemote runs the target's own karma in its local mode and streams the
// report through. The run options travel as flags, so the operator's
// --timeout, --concurrency and --max-lines hold on the target too.
func runRemote(ctx context.Context, streamer session.Streamer, remote string, options model.RunOptions, selectors []string) error {
	words := []string{remote, "local",
		"--timeout", strconv.FormatFloat(options.Timeout.Seconds(), 'f', -1, 64),
		"--concurrency", strconv.Itoa(options.Concurrency),
		"--max-lines", strconv.Itoa(options.MaxLines),
	}
	words = append(words, selectors...)
	code, err := streamer.Stream(ctx, model.Shell{Script: script.Join(words)}, os.Stdout, os.Stderr)
	if err != nil {
		return err
	}
	if code != 0 {
		return failf(code, "the target's karma exited with %d", code)
	}
	return nil
}

// cleanUp removes the uploaded directory. The cancellation is detached: the
// interrupt that ended the run is exactly the case that must still clean up,
// and the removal is a fresh short call of its own.
func cleanUp(ctx context.Context, sess session.Session, dir string, keep bool) {
	if keep {
		fmt.Fprintf(os.Stderr, "karma: %s left on the target\n", dir)
		return
	}
	cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bootstrapTimeout)
	defer cancel()
	_ = sess.Run(cleanCtx, model.Shell{Script: script.Join([]string{"rm", "-rf", dir})}, bootstrapTimeout, 0)
}

// unamePlatform maps `uname -s -m` to the GOOS/GOARCH pair a binary must be
// built for; an unknown machine name is an error rather than a guess, because
// the run would fail on the target.
func unamePlatform(system, machine string) (string, string, error) {
	goos := map[string]string{
		"Linux": "linux", "Darwin": "darwin", "FreeBSD": "freebsd",
		"OpenBSD": "openbsd", "NetBSD": "netbsd", "SunOS": "solaris",
	}[system]
	if goos == "" {
		return "", "", fmt.Errorf("unsupported target system %q", system)
	}
	goarch := map[string]string{
		"x86_64": "amd64", "amd64": "amd64",
		"i386": "386", "i486": "386", "i586": "386", "i686": "386",
		"aarch64": "arm64", "arm64": "arm64",
		"armv6l": "arm", "armv7l": "arm", "armv8l": "arm",
		"riscv64": "riscv64", "ppc64le": "ppc64le", "ppc64": "ppc64", "s390x": "s390x",
		"mips": "mips", "mips64": "mips64", "loongarch64": "loong64",
	}[machine]
	if goarch == "" {
		return "", "", fmt.Errorf("unsupported target machine %q", machine)
	}
	return goos, goarch, nil
}

// randomSuffix names the upload directory: a fresh path per run, so a leftover
// from an interrupted one is never overwritten.
func randomSuffix() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(raw[:])
}
