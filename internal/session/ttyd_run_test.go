// The ttyd channel's run-path tests: an in-process fake ttyd speaking the
// real frame protocol around /bin/sh, with a simulated pty (typed input echoed
// back, the child's newlines becoming CRLF). The fake needs a POSIX shell, so
// it lives behind the unix build tag.

//go:build unix

package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"

	"karma/internal/model"
)

// fakeTTYD is the server side of the protocol: Basic auth on the upgrade when
// a credential is set, the AuthToken check on the JSON handshake, title and
// preferences after spawn, INPUT frames echoed and fed to /bin/sh, the shell's
// merged output returned as OUTPUT frames with CRLF. readonly drops INPUT the
// way ttyd without -W does.
type fakeTTYD struct {
	addr       string
	credential string
	readonly   bool
}

func newFakeTTYD(t *testing.T, credential string, readonly bool) *fakeTTYD {
	t.Helper()
	fake := &fakeTTYD{credential: credential, readonly: readonly}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fake.addr = listener.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", fake.serve)
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return fake
}

func (f *fakeTTYD) url() string { return "ws://" + f.addr + "/ws" }

func (f *fakeTTYD) serve(w http.ResponseWriter, r *http.Request) {
	if f.credential != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(f.credential))
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"tty"}})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx := r.Context()

	msgType, reader, err := conn.Reader(ctx)
	if err != nil || msgType != websocket.MessageBinary {
		return
	}
	handshake, err := io.ReadAll(reader)
	if err != nil || len(handshake) == 0 || handshake[0] != '{' {
		return
	}
	if f.credential != "" {
		var parsed struct{ AuthToken string }
		_ = json.Unmarshal(handshake, &parsed)
		if parsed.AuthToken != base64.StdEncoding.EncodeToString([]byte(f.credential)) {
			_ = conn.Close(websocket.StatusPolicyViolation, "")
			return
		}
	}

	// The shell runs in its own session with no controlling terminal, the way
	// ttyd's forkpty child does — the payload's </dev/tty probe must find
	// nothing here rather than the test runner's own terminal.
	command := exec.Command("/bin/sh")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdin, err := command.StdinPipe()
	if err != nil {
		return
	}
	// One merged output pipe, the way a pty presents it: both streams in
	// their real order, not two pipes racing.
	outputReader, outputWriter, err := os.Pipe()
	if err != nil {
		return
	}
	command.Stdout = outputWriter
	command.Stderr = outputWriter
	if err := command.Start(); err != nil {
		return
	}
	_ = outputWriter.Close()

	// The write lock keeps the echo and the output pump on one writer.
	var writeMu sync.Mutex
	write := func(payload []byte) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.Write(ctx, websocket.MessageBinary, payload)
	}

	write([]byte("1/bin/sh (fake)"))
	write([]byte("2{ }"))

	merged := make(chan []byte, 16)
	var pumps sync.WaitGroup
	pumps.Add(1)
	go func() {
		defer pumps.Done()
		for {
			chunk := make([]byte, 4096)
			n, err := outputReader.Read(chunk)
			if n > 0 {
				merged <- chunk[:n]
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		for chunk := range merged {
			write(append([]byte{'0'}, bytes.ReplaceAll(chunk, []byte("\n"), []byte("\r\n"))...))
		}
	}()

	for {
		_, reader, err := conn.Reader(ctx)
		if err != nil {
			break
		}
		frame, err := io.ReadAll(reader)
		if err != nil || len(frame) == 0 || frame[0] != '0' {
			continue
		}
		if f.readonly {
			continue
		}
		write(append([]byte{'0'}, bytes.ReplaceAll(frame[1:], []byte("\n"), []byte("\r\n"))...))
		_, _ = stdin.Write(frame[1:])
	}
	// The child's death ends the pumps, the pumps' end closes the output
	// path: this order keeps every send inside the channel's lifetime.
	_ = command.Process.Kill()
	_, _ = command.Process.Wait()
	pumps.Wait()
	close(merged)
}

// openTTYD opens a transport against a fake, failing the test on any error.
func openTTYD(t *testing.T, target, credential string) Session {
	t.Helper()
	sess, err := (&TTYDTransport{Target: target, Credential: credential}).Open()
	if err != nil {
		t.Fatalf("open the ttyd channel: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func TestTTYDSessionMeta(t *testing.T) {
	sess := openTTYD(t, newFakeTTYD(t, "", false).url(), "")
	if sess.Name() != "ttyd" {
		t.Fatalf("name: %q", sess.Name())
	}
	if sess.Channel() != model.ChanTTYD || !sess.Channel().Remote() {
		t.Fatalf("channel: %v", sess.Channel())
	}
}

func TestTTYDRunCollectsBodyAndExitCode(t *testing.T) {
	sess := openTTYD(t, newFakeTTYD(t, "", false).url(), "")
	result := sess.Run(context.Background(), model.Shell{Script: "echo hello; echo oops 1>&2; exit 3"}, 10*time.Second, 0)
	if result.Stdout != "hello\n" {
		t.Fatalf("stdout: %q", result.Stdout)
	}
	if result.Stderr != "oops\n" {
		t.Fatalf("stderr: %q", result.Stderr)
	}
	if result.ExitCode != 3 {
		t.Fatalf("exit code: %d", result.ExitCode)
	}
	if result.TimedOut || result.Truncated {
		t.Fatalf("flags: %+v", result)
	}
	if strings.Contains(result.Stdout, "__KRM") || strings.Contains(result.Stdout, "base64") {
		t.Fatalf("marker or typed line leaked into the body: %q", result.Stdout)
	}
}

// The pty merges the streams; the channel must split them back. An error line
// reaching stdout would make a failed tier count as answered and stop the
// fallback chain, so a missing binary keeps the ssh channel's shape: empty
// stdout, the shell's complaint on stderr, exit 127.
func TestTTYDRunSeparatesStderrFromStdout(t *testing.T) {
	sess := openTTYD(t, newFakeTTYD(t, "", false).url(), "")
	result := sess.Run(context.Background(), model.Shell{Script: "echo first; nosuchbinary-karma; echo last"}, 10*time.Second, 0)
	if result.Stdout != "first\nlast\n" {
		t.Fatalf("stdout: %q", result.Stdout)
	}
	if !strings.Contains(result.Stderr, "nosuchbinary-karma") {
		t.Fatalf("stderr: %q", result.Stderr)
	}
	missing := sess.Run(context.Background(), model.Shell{Script: "nosuchbinary-karma"}, 10*time.Second, 0)
	if missing.Stdout != "" || !strings.Contains(missing.Stderr, "not found") || missing.ExitCode != 127 {
		t.Fatalf("a missing binary must answer like the ssh channel: %+v", missing)
	}
}

func TestTTYDRunTimesOutAndKeepsPartialOutput(t *testing.T) {
	sess := openTTYD(t, newFakeTTYD(t, "", false).url(), "")
	result := sess.Run(context.Background(), model.Shell{Script: "echo one; sleep 5; echo two"}, 1500*time.Millisecond, 0)
	if !strings.Contains(result.Stdout, "one") || strings.Contains(result.Stdout, "two") {
		t.Fatalf("stdout: %q", result.Stdout)
	}
	if !result.TimedOut || result.ExitCode != -1 {
		t.Fatalf("result: %+v", result)
	}
}

func TestTTYDRunKeepsTrailingPartialLine(t *testing.T) {
	sess := openTTYD(t, newFakeTTYD(t, "", false).url(), "")
	result := sess.Run(context.Background(), model.Shell{Script: "printf tail"}, 10*time.Second, 0)
	if result.Stdout != "tail" || result.ExitCode != 0 {
		t.Fatalf("result: %+v", result)
	}
}

func TestTTYDRunNormalizesCarriageReturns(t *testing.T) {
	sess := openTTYD(t, newFakeTTYD(t, "", false).url(), "")
	// The fake's pty already turns every \n into \r\n; the channel must put
	// the plain line endings back so the reading layers see the ssh shape.
	result := sess.Run(context.Background(), model.Shell{Script: "printf 'x\\ty\\nz\\n'"}, 10*time.Second, 0)
	if result.Stdout != "x\ty\nz\n" {
		t.Fatalf("stdout: %q", result.Stdout)
	}
}

func TestTTYDRunTypesLongLines(t *testing.T) {
	sess := openTTYD(t, newFakeTTYD(t, "", false).url(), "")
	script := strings.Repeat("# padding to push the typed line past one chunk\n", 120) + "echo done"
	result := sess.Run(context.Background(), model.Shell{Script: script}, 10*time.Second, 0)
	if !strings.Contains(result.Stdout, "done") || result.ExitCode != 0 {
		t.Fatalf("result: code=%d stdout=%q", result.ExitCode, result.Stdout)
	}
}

func TestTTYDProbeRejectsReadonlyServer(t *testing.T) {
	oldWindow := ttydProbeWindow
	ttydProbeWindow = 600 * time.Millisecond
	t.Cleanup(func() { ttydProbeWindow = oldWindow })
	_, err := (&TTYDTransport{Target: newFakeTTYD(t, "", true).url()}).Open()
	if err == nil || !strings.Contains(err.Error(), "readonly") {
		t.Fatalf("error: %v", err)
	}
}

func TestTTYDAuthorization(t *testing.T) {
	fake := newFakeTTYD(t, "u:p", false)
	if _, err := (&TTYDTransport{Target: fake.url(), Credential: "u:wrong"}).Open(); err == nil {
		t.Fatal("a wrong credential must fail the connection")
	}
	sess := openTTYD(t, fake.url(), "u:p")
	result := sess.Run(context.Background(), model.Shell{Script: "echo authed"}, 10*time.Second, 0)
	if result.Stdout != "authed\n" || result.ExitCode != 0 {
		t.Fatalf("result: %+v", result)
	}
}

func TestTTYDTargetUnreachable(t *testing.T) {
	// Port 1 on the loopback refuses connections without needing a listener.
	_, err := (&TTYDTransport{Target: "ws://127.0.0.1:1/ws"}).Open()
	if err == nil {
		t.Fatal("an unreachable endpoint must fail the open")
	}
}
