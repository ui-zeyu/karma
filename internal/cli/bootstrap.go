// Bootstrap: put this binary on the target, so the operator can run karma
// there. The uploaded program reads the kernel's interfaces in process — no
// shell, no coreutils and no libc in the path — which is what makes it usable
// on a host where those cannot be trusted, and a collection over a channel
// never does that, so this mode is the only way a remote host gets the native
// source's reading (userland rootkit detection among them).
//
// The transfer rides the channel itself: ssh streams the file over the
// session's stdin, ttyd types it into the terminal it already has. The bytes
// travel gzip-compressed whenever the target can unpack them — its own gzip, or
// busybox's — which is what makes the mode bearable over a slow link; a target
// with neither gets the plain binary, so nothing about the mode depends on what
// the host happens to have installed. Either way the upload is verified twice
// before the path is printed: by the decompressor's own checksum when there is
// one (a transfer that lost or changed a byte cannot pass), and by the binary's
// version line (the file is executable and is this build).
//
// Where the file goes is place.go's business: the account's own directory first,
// then /tmp, reused when a copy is already there and proved to be this build.
// Nothing is run on the target: the mode places and reports the path.

package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"karma/internal/model"
	"karma/internal/script"
	"karma/internal/session"
)

// bootstrapTimeout bounds one small command around the transfer — uname, the
// decompression, the version probe. The transfer itself carries no deadline:
// it is bounded by the link and by the operator's interrupt.
const bootstrapTimeout = 60 * time.Second

// bootCall runs one bootstrap command under the mode's own budget: the mode
// makes a handful of small calls around the upload, and none of them is the
// collection's business.
func bootCall(ctx context.Context, sess session.Session, inv model.Invocation) model.RunResult {
	ctx, cancel := session.Within(ctx, bootstrapTimeout)
	defer cancel()
	return sess.Run(ctx, model.Call{Inv: inv})
}

// runBootstrap places this binary on the target and prints where it landed.
func runBootstrap(ctx context.Context, transport session.Transport) error {
	sess, err := transport.Open(ctx)
	if err != nil {
		return err
	}
	defer sess.Close()
	path, reused, err := placeBinary(ctx, sess)
	if err != nil {
		return err
	}
	if reused {
		fmt.Printf("karma %s is already at %s (md5 verified)\n", buildVersion, path)
	} else {
		fmt.Printf("karma %s placed at %s\n", buildVersion, path)
	}
	fmt.Printf("run it on the target yourself, for example: %s local\n", path)
	return nil
}

// transfer is what the mode sends and how the target turns it into the program:
// body lands at path, and unpack, when there is one, decompresses it in place.
type transfer struct {
	body   []byte
	path   string
	unpack string
}

// planTransfer picks the encoding with one probe. gzip is the rule wherever the
// target can unpack it — its own gzip or busybox's, since that is what keeps the
// transfer small; a target with neither still works, at the price of the full
// binary on the wire, which asks for nothing beyond the shell, cat and chmod
// every channel already uses. The program is the caller's bytes, so what the
// plan carries is decided without reading this process's own binary first.
func planTransfer(ctx context.Context, sess session.Session, remote string, program []byte) (transfer, error) {
	packer := targetPacker(ctx, sess)
	if packer == "none" {
		fmt.Fprintf(os.Stderr,
			"karma: the target has neither gzip nor busybox, so the %d MB binary travels uncompressed\n",
			len(program)>>20)
		return transfer{body: program, path: remote}, nil
	}
	archive, err := gzipBytes(program)
	if err != nil {
		return transfer{}, err
	}
	command := []string{"gzip", "-d", "-f", remote + ".gz"}
	if packer == "busybox" {
		command = []string{"busybox", "gunzip", "-f", remote + ".gz"}
	}
	return transfer{body: archive, path: remote + ".gz", unpack: script.Join(command)}, nil
}

// packerProbe names the target's decompressor in one word.
const packerProbe = `if command -v gzip >/dev/null 2>&1; then echo gzip
elif command -v busybox >/dev/null 2>&1; then echo busybox
else echo none
fi`

// targetPacker reports how the target unpacks a gzip stream: its own gzip,
// busybox's, or none at all.
func targetPacker(ctx context.Context, sess session.Session) string {
	result := bootCall(ctx, sess, model.Shell{Script: packerProbe})
	switch packer := strings.TrimSpace(result.Stdout); packer {
	case "gzip", "busybox":
		return packer
	}
	return "none"
}

// gzipBytes compresses the binary at the best level the local side can afford:
// the link is almost always slower than the compression, and a static karma is
// mostly tables and code, so gzip takes it to well under half.
func gzipBytes(content []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	// The gzip header carries no name: the target unpacks the file it was
	// given, whose name is the one this command chose.
	if _, err := writer.Write(content); err != nil {
		return nil, fmt.Errorf("compressing the binary: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("compressing the binary: %w", err)
	}
	return buf.Bytes(), nil
}

// unpackUpload turns the upload into the program and proves it is this build.
// The decompressor verifies the archive's checksum and length as it writes, so
// a truncated or corrupted transfer fails here, and the version line then fails
// a file that is not the program it claims to be.
func unpackUpload(ctx context.Context, sess session.Session, remote, unpack string) error {
	command := script.Join([]string{"chmod", "700", remote})
	if unpack != "" {
		command = unpack + " && " + command
	}
	if result := bootCall(ctx, sess, model.Shell{Script: command}); result.Verdict != model.VerdictAnswered {
		return fmt.Errorf("unpacking the upload: %s", commandFailure(result))
	}
	result := bootCall(ctx, sess, model.Shell{Script: script.Join([]string{remote, "version"})})
	want := "karma " + buildVersion
	if got := strings.TrimSpace(result.Stdout); got != want {
		return fmt.Errorf("the uploaded binary answered %q, want %q: %s", got, want, commandFailure(result))
	}
	return nil
}

// commandFailure renders what a failed small command said: the target's own
// stderr, its exit status when the channel carried no text, or the verdict when
// the call never ran a process at all.
func commandFailure(result model.RunResult) string {
	if text := strings.TrimSpace(result.Stderr); text != "" {
		return text
	}
	switch result.Verdict {
	case model.VerdictUnavailable:
		return "the target does not have that command"
	case model.VerdictTimedOut:
		return "the target did not answer before the deadline"
	case model.VerdictInterrupted:
		return "interrupted"
	}
	return fmt.Sprintf("the target exited with %d", result.ExitCode)
}

// targetPlatform reads the target's kernel and machine and maps them to the
// GOOS/GOARCH pair a binary must be built for. A cross-arch run cannot happen,
// and the mistake belongs to this command rather than to a failed exec on the
// target.
func targetPlatform(ctx context.Context, sess session.Session) (string, string, error) {
	result := bootCall(ctx, sess, model.Shell{Script: "uname -s -m"})
	fields := strings.Fields(result.Stdout)
	if len(fields) < 2 {
		return "", "", fmt.Errorf("cannot read the target's platform (uname said %q)", strings.TrimSpace(result.Stdout))
	}
	return unamePlatform(fields[0], fields[1])
}

// unameGOOS and unameGOARCH map `uname -s -m`'s words to the GOOS/GOARCH pair
// a binary must be built for.
var (
	unameGOOS = map[string]string{
		"Linux": "linux", "Darwin": "darwin", "FreeBSD": "freebsd",
		"OpenBSD": "openbsd", "NetBSD": "netbsd", "SunOS": "solaris",
	}
	unameGOARCH = map[string]string{
		"x86_64": "amd64", "amd64": "amd64",
		"i386": "386", "i486": "386", "i586": "386", "i686": "386",
		"aarch64": "arm64", "arm64": "arm64",
		"armv6l": "arm", "armv7l": "arm", "armv8l": "arm",
		"riscv64": "riscv64", "ppc64le": "ppc64le", "ppc64": "ppc64", "s390x": "s390x",
		"mips": "mips", "mips64": "mips64", "loongarch64": "loong64",
	}
)

// unamePlatform maps `uname -s -m` to the GOOS/GOARCH pair a binary must be
// built for; an unknown machine name is an error rather than a guess, because
// the run would fail on the target.
func unamePlatform(system, machine string) (string, string, error) {
	goos := unameGOOS[system]
	if goos == "" {
		return "", "", fmt.Errorf("unsupported target system %q", system)
	}
	goarch := unameGOARCH[machine]
	if goarch == "" {
		return "", "", fmt.Errorf("unsupported target machine %q", machine)
	}
	return goos, goarch, nil
}
