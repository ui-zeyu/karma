// Bootstrap's own pieces: the platform gate that keeps a cross-arch upload
// from reaching the target, the mode split that puts the form after the target
// the way mtime does, and the archive that travels.

package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"runtime"
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/session"
)

// probeSession answers the packer probe with what a target reported and records
// every command the mode ran there.
type probeSession struct {
	answer string
	ran    []string
}

func (s *probeSession) Name() string           { return "probe" }
func (s *probeSession) Channel() model.Channel { return model.ChanSSH }

func (s *probeSession) Describe() string { return "ssh" }
func (s *probeSession) Close() error     { return nil }

func (s *probeSession) Run(_ context.Context, call model.Call) model.RunResult {
	inv := call.Inv
	command := session.RenderShell(inv)
	s.ran = append(s.ran, command)
	if strings.Contains(command, "command -v gzip") {
		return model.RunResult{Verdict: model.VerdictAnswered, Stdout: s.answer + "\n"}
	}
	return model.RunResult{Verdict: model.VerdictAnswered}
}

func TestUnamePlatformMapsTheTargetsKernelAndMachine(t *testing.T) {
	cases := []struct {
		system, machine string
		goos, goarch    string
	}{
		{"Linux", "x86_64", "linux", "amd64"},
		{"Linux", "aarch64", "linux", "arm64"},
		{"Linux", "armv7l", "linux", "arm"},
		{"Linux", "i686", "linux", "386"},
		{"Linux", "riscv64", "linux", "riscv64"},
		{"Darwin", "arm64", "darwin", "arm64"},
		{"FreeBSD", "x86_64", "freebsd", "amd64"},
	}
	for _, c := range cases {
		goos, goarch, err := unamePlatform(c.system, c.machine)
		if err != nil {
			t.Errorf("unamePlatform(%q, %q): %v", c.system, c.machine, err)
			continue
		}
		if goos != c.goos || goarch != c.goarch {
			t.Errorf("unamePlatform(%q, %q) = %s/%s, want %s/%s",
				c.system, c.machine, goos, goarch, c.goos, c.goarch)
		}
	}
}

// An unknown name is an error rather than a guess: a wrong guess means a binary
// that cannot exec on the target.
func TestUnamePlatformRejectsUnknownNames(t *testing.T) {
	for _, c := range [][2]string{{"Plan9", "x86_64"}, {"Linux", "sparc64"}, {"", ""}} {
		if _, _, err := unamePlatform(c[0], c[1]); err == nil {
			t.Errorf("unamePlatform(%q, %q) was accepted", c[0], c[1])
		}
	}
}

// The mode word splits each channel's positional arguments the same way: the
// words after it belong to the mode, and a selector is not a mode word.
func TestModeArgsSplitsTheMode(t *testing.T) {
	if extra, ok := modeArgs([]string{"bootstrap"}, "bootstrap"); !ok || len(extra) != 0 {
		t.Fatalf("a bare bootstrap form = %v, %v", extra, ok)
	}
	if extra, ok := modeArgs([]string{"bootstrap", "identity"}, "bootstrap"); !ok || len(extra) != 1 {
		t.Fatalf("the words after bootstrap = %v, %v", extra, ok)
	}
	if _, ok := modeArgs([]string{"identity"}, "bootstrap"); ok {
		t.Fatal("a selector was taken for the bootstrap form")
	}
	if _, ok := modeArgs(nil, "bootstrap"); ok {
		t.Fatal("no arguments were taken for the bootstrap form")
	}
	if dirs, ok := modeArgs([]string{"mtime", "/tmp"}, "mtime"); !ok || len(dirs) != 1 {
		t.Fatalf("the mtime form = %v, %v", dirs, ok)
	}
}

// The mode uploads and stops; a selector or --save would suggest a run that
// does not happen, so each is refused rather than ignored.
func TestBootstrapModeRefusesARunOfItsOwn(t *testing.T) {
	if err := runBootstrapMode(newSSHCmd(), nil, []string{"identity"}); err == nil {
		t.Fatal("a selector after bootstrap was accepted")
	}
	cmd := newSSHCmd()
	if err := cmd.Flags().Set("save", "/tmp/karma-save"); err != nil {
		t.Fatal(err)
	}
	if err := runBootstrapMode(cmd, nil, nil); err == nil {
		t.Fatal("--save was accepted by bootstrap")
	}
}

// The archive is what travels when the target can unpack it: a gzip stream
// whose unpacked bytes are the program again, so the target's decompressor can
// verify the transfer by its checksum.
func TestGzipBytesUnpacksToTheProgram(t *testing.T) {
	program := bytes.Repeat([]byte("karma archive "), 4096)
	archive, err := gzipBytes(program)
	if err != nil {
		t.Fatalf("gzipBytes: %v", err)
	}
	if len(archive) == 0 {
		t.Fatal("the archive is empty")
	}
	if len(archive) >= len(program) {
		t.Fatalf("the archive holds %d bytes for a %d-byte program", len(archive), len(program))
	}
	reader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("the archive is not a gzip stream: %v", err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading the archive: %v", err)
	}
	if !bytes.Equal(got, program) {
		t.Fatalf("the archive unpacks to %d bytes, want the program's %d", len(got), len(program))
	}
}

// The probe names the target's decompressor, and the unpack command follows it:
// a target with neither program still gets the binary, uncompressed, which is
// the whole point of not depending on the host.
func TestPackerProbeNamesADecompressorOrNone(t *testing.T) {
	for _, want := range []string{"gzip", "busybox", "none"} {
		if !strings.Contains(packerProbe, "echo "+want) {
			t.Errorf("the probe never answers %q: %s", want, packerProbe)
		}
	}
	if !strings.Contains(packerProbe, "command -v gzip") || !strings.Contains(packerProbe, "command -v busybox") {
		t.Errorf("the probe does not look for both programs: %s", packerProbe)
	}
}

// planTransfer is the mode's whole dependency story: gzip when the target's own
// gzip can unpack it, busybox's when that is what the target has, and the plain
// program — with an uncompressed transfer — when it has neither. The payload is
// the test's own, so the choice and the body are driven without compressing this
// test binary.
func TestPlanTransferFollowsTheTargetsDecompressor(t *testing.T) {
	remote := "/tmp/karma-x/karma"
	program := bytes.Repeat([]byte("karma archive "), 4096)
	cases := []struct {
		answer string
		path   string
		unpack string
		plural string
	}{
		{"gzip", remote + ".gz", "gzip -d -f /tmp/karma-x/karma.gz", "gzipped"},
		{"busybox", remote + ".gz", "busybox gunzip -f /tmp/karma-x/karma.gz", "gzipped"},
		{"none", remote, "", "plain"},
	}
	for _, c := range cases {
		sess := &probeSession{answer: c.answer}
		got, err := planTransfer(context.Background(), sess, remote, program)
		if err != nil {
			t.Fatalf("%s: planTransfer: %v", c.answer, err)
		}
		if got.path != c.path || got.unpack != c.unpack {
			t.Errorf("%s: path/unpack = %q/%q, want %q/%q", c.answer, got.path, got.unpack, c.path, c.unpack)
		}
		switch c.plural {
		case "gzipped":
			if len(got.body) >= len(program) {
				t.Errorf("%s: the body is %d bytes, not compressed", c.answer, len(got.body))
			}
		case "plain":
			if !bytes.Equal(got.body, program) {
				t.Errorf("%s: the body is %d bytes, want the program's %d", c.answer, len(got.body), len(program))
			}
		}
		if len(sess.ran) != 1 || !strings.Contains(sess.ran[0], "command -v gzip") {
			t.Errorf("%s: the probe ran %q, want one probe command", c.answer, sess.ran)
		}
	}
}

// theTargetAndThisBuild is a target that is not this binary's platform: the
// machine name is chosen from this build, so the mismatch holds on any host.
func theTargetAndThisBuild() string {
	if runtime.GOARCH == "amd64" {
		return "Linux aarch64"
	}
	return "Linux x86_64"
}

// commandSession answers each command by the first of the given patterns it
// contains, and records what the mode ran.
type commandSession struct {
	answers []struct {
		match  string
		result model.RunResult
	}
	ran []string
}

func (s *commandSession) Name() string           { return "command" }
func (s *commandSession) Channel() model.Channel { return model.ChanSSH }

func (s *commandSession) Describe() string { return "ssh" }
func (s *commandSession) Close() error     { return nil }

func (s *commandSession) Run(_ context.Context, call model.Call) model.RunResult {
	inv := call.Inv
	command := session.RenderShell(inv)
	s.ran = append(s.ran, command)
	for _, answer := range s.answers {
		if strings.Contains(command, answer.match) {
			return answer.result
		}
	}
	return model.RunResult{Verdict: model.VerdictAnswered}
}

// A target of another architecture cannot run this binary, and the mistake is
// cheaper to catch here than as a failed exec on the host.
func TestCheckTargetPlatformRefusesAMismatch(t *testing.T) {
	sess := &commandSession{answers: []struct {
		match  string
		result model.RunResult
	}{{match: "uname -s -m", result: model.RunResult{Verdict: model.VerdictAnswered, Stdout: theTargetAndThisBuild() + "\n"}}}}
	err := checkTargetPlatform(context.Background(), sess)
	if err == nil {
		t.Fatal("a cross-arch target was accepted")
	}
	if !strings.Contains(err.Error(), "GOOS=") || !strings.Contains(err.Error(), "bootstrap that build") {
		t.Fatalf("the refusal should say how to build for the target: %v", err)
	}
}

// A target whose uname says nothing (a stripped container) is refused with what
// it did say, rather than uploaded to and failed on.
func TestCheckTargetPlatformNeedsBothFields(t *testing.T) {
	sess := &commandSession{answers: []struct {
		match  string
		result model.RunResult
	}{{match: "uname -s -m", result: model.RunResult{Verdict: model.VerdictAnswered, Stdout: "Linux\n"}}}}
	if err := checkTargetPlatform(context.Background(), sess); err == nil {
		t.Fatal("a target with no machine name was accepted")
	}
}

// The compressor's checksum is the first verification: a transfer the target
// could not unpack stops here, with the target's own words.
func TestUnpackUploadReportsAFailedDecompressor(t *testing.T) {
	sess := &commandSession{answers: []struct {
		match  string
		result model.RunResult
	}{{match: "gzip -d -f", result: model.RunResult{
		Stderr: "gzip: stdin: not in gzip format", ExitCode: 1}}}}
	err := unpackUpload(context.Background(), sess, "/tmp/karma-x/karma", "gzip -d -f /tmp/karma-x/karma.gz")
	if err == nil || !strings.Contains(err.Error(), "not in gzip format") {
		t.Fatalf("a failed unpack should carry the target's words: %v", err)
	}
}

// The version line is the second verification: a file that runs but is not this
// build (a stale copy, a wrapper) is refused.
func TestUnpackUploadRefusesAnotherBuild(t *testing.T) {
	previous := buildVersion
	buildVersion = "9.9.9"
	defer func() { buildVersion = previous }()
	sess := &commandSession{answers: []struct {
		match  string
		result model.RunResult
	}{{match: "version", result: model.RunResult{Verdict: model.VerdictAnswered, Stdout: "karma 0.1.0\n"}}}}
	err := unpackUpload(context.Background(), sess, "/tmp/karma-x/karma", "")
	if err == nil {
		t.Fatal("a binary that answered another version was accepted")
	}
	if !strings.Contains(err.Error(), "karma 9.9.9") || !strings.Contains(err.Error(), "karma 0.1.0") {
		t.Fatalf("the refusal should name both versions: %v", err)
	}
}

// A failing small command reports the target's stderr, and falls back to the
// exit status when the channel carried no text.
func TestCommandFailurePrefersTheTargetsWords(t *testing.T) {
	withText := commandFailure(model.RunResult{Stderr: " cat: /tmp/x: No such file \n", ExitCode: 1})
	if withText != "cat: /tmp/x: No such file" {
		t.Fatalf("commandFailure = %q", withText)
	}
	withoutText := commandFailure(model.RunResult{ExitCode: 7})
	if !strings.Contains(withoutText, "7") {
		t.Fatalf("a silent failure should report the exit status: %q", withoutText)
	}
	// A call that never ran a process has no status to report: the verdict is
	// what the message can say.
	missing := commandFailure(model.RunResult{Verdict: model.VerdictUnavailable, ExitCode: 127})
	if !strings.Contains(missing, "does not have that command") {
		t.Fatalf("an unavailable command should say so: %q", missing)
	}
}
