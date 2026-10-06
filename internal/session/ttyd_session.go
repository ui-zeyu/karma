// TTYDSession: the ttyd channel's run path. One websocket connection per
// call, one typed line per call, the body cut out between markers, the exit
// code read from the rc marker — the pty merges the streams and drops the
// numeric exit status, so the payload puts both back.

package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"karma/internal/model"
	"karma/internal/script"
)

const (
	// The handshake's window size, landed in the pty's winsize: wide enough
	// that nothing the collection prints wraps at the terminal edge.
	ttydColumns = 500
	ttydRows    = 50
	// ttydSpawnWait bounds the wait for the server's initial messages, which
	// prove the terminal's process was spawned: input sent before the spawn
	// is dropped (a pty write to a process that does not exist yet).
	ttydSpawnWait = 2 * time.Second
	// ttydTypeaheadDelay lets the spawned shell's line editor take the tty
	// over before the line arrives: bytes queued while the line discipline is
	// still canonical are capped near 4 KiB per pending line.
	ttydTypeaheadDelay = 150 * time.Millisecond
	// ttydWriteChunk splits the typed line with pauses, so each pending burst
	// stays under that cap until the shell drains the previous chunk.
	ttydWriteChunk = 1024
	ttydChunkPause = 15 * time.Millisecond
)

// TTYDSession is the ttyd channel: the dialled endpoint and its credential
// material. Connections are per call — each websocket connection is one
// terminal process, so every Run gets a fresh shell the way the ssh channel
// opens one session per call, and a hung call only ever closes its own
// connection.
type TTYDSession struct {
	endpoint string
	token    string // base64 credential, the handshake's AuthToken
	header   http.Header
	client   *http.Client
}

// Name is the channel display name.
func (s *TTYDSession) Name() string { return "ttyd" }

// Describe names the channel and the endpoint it reached. The endpoint carries
// no credential: ParseTTYDEndpoint strips the userinfo out of the URL before it
// is stored.
func (s *TTYDSession) Describe() string {
	if s.endpoint == "" {
		return "ttyd"
	}
	return "ttyd " + s.endpoint
}

// Channel is which side of the wire karma runs on: the target is remote.
func (s *TTYDSession) Channel() model.Channel { return model.ChanTTYD }

// Close releases the channel's resources: connections live per call.
func (s *TTYDSession) Close() error { return nil }

// Run types one collection line into a fresh terminal and harvests the answer.
func (s *TTYDSession) Run(ctx context.Context, inv model.Invocation, timeout time.Duration, lineLimit int) model.RunResult {
	conn, err := s.connect(ctx)
	if err != nil {
		return model.RunResult{Stderr: fmt.Sprintf("ttyd channel error: %v", err), ExitCode: -1}
	}
	call := &ttydCall{conn: conn, spawned: make(chan struct{})}
	return call.collect(ctx, bodyText(inv), timeout, lineLimit)
}

// connect dials the endpoint and sends the JSON handshake. ttyd spawns the
// terminal's process on this message; the AuthToken satisfies the second auth
// layer when a credential is set (the Basic header on the upgrade is the
// first), and the window size reaches the pty's winsize.
func (s *TTYDSession) connect(ctx context.Context) (*websocket.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, ttydDialTimeout)
	defer cancel()
	conn, _, err := websocket.Dial(dialCtx, s.endpoint, &websocket.DialOptions{
		HTTPClient:   s.client,
		HTTPHeader:   s.header,
		Subprotocols: []string{"tty"},
	})
	if err != nil {
		return nil, err
	}
	handshake := fmt.Sprintf(`{"AuthToken":%q,"columns":%d,"rows":%d}`, s.token, ttydColumns, ttydRows)
	if err := conn.Write(dialCtx, websocket.MessageBinary, []byte(handshake)); err != nil {
		conn.CloseNow()
		return nil, err
	}
	return conn, nil
}

// The upload conversation: raw mode first (a payload this size cannot go
// through the canonical-mode line buffer), then the base64 body read straight
// off the tty, and a marker for each outcome. ttydUploadWait bounds the wait for
// a marker; ttydUploadChunk and ttydUploadPause pace the typed body.
const (
	ttydUploadWait  = 60 * time.Second
	ttydUploadChunk = 8192
	ttydUploadPause = 2 * time.Millisecond
)

// Upload writes one file to the target through the terminal: the setup script
// is typed as one line, then the base64 body is typed raw and read by head(1)
// from the tty. The pty merges the streams and has no exit status, so the
// script reports each step with a marker instead.
func (s *TTYDSession) Upload(ctx context.Context, path string, content []byte) error {
	encoded := base64.StdEncoding.EncodeToString(content)
	token := markerSalt()
	ready := "__KRM_" + token + "_READY__"
	done := "__KRM_" + token + "_DONE__"
	failed := "__KRM_" + token + "_FAIL__"
	// The script goes to the target as a file and is run with the terminal as
	// its stdin, so head(1) reads the typed body straight off the tty; a
	// pipeline into /bin/sh would leave it reading this line's decoded text.
	dir := filepath.Dir(path)
	setup := fmt.Sprintf("umask 077; %s; KARMA_UPLOAD=%s; export KARMA_UPLOAD; printf %%s %s | base64 -d > %s && /bin/sh %s",
		script.Join([]string{"mkdir", "-p", dir}),
		script.Join([]string{path}),
		base64.StdEncoding.EncodeToString([]byte(ttydUploadScript(len(encoded), ready, done, failed))),
		script.Join([]string{filepath.Join(dir, "upload.sh")}),
		script.Join([]string{filepath.Join(dir, "upload.sh")}))

	conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	call := &ttydCall{conn: conn, spawned: make(chan struct{})}
	// The pump owns the read side for the whole conversation: the echo of the
	// typed body is a flood, and the bytes that matter are the markers. It has
	// to run while the body is typed, so the terminal's own buffer never fills
	// up on output nobody reads.
	found := make(chan string, 4)
	failure := make(chan error, 1)
	go call.pumpFrames(ctx, []string{ready, done, failed}, found, failure)

	select {
	case <-call.spawned:
	case err := <-failure:
		return err
	case <-time.After(ttydSpawnWait):
	case <-ctx.Done():
		return ctx.Err()
	}
	time.Sleep(ttydTypeaheadDelay)
	if err := call.typeLine(ctx, setup); err != nil {
		return err
	}
	deadline := time.Now().Add(ttydUploadWait)
	if _, err := awaitMarker(ctx, found, failure, deadline, ready); err != nil {
		return fmt.Errorf("the target's shell never started the upload: %w", err)
	}
	if err := call.typeBody(ctx, encoded); err != nil {
		return err
	}
	marker, err := awaitMarker(ctx, found, failure, deadline, done, failed)
	if err != nil {
		return fmt.Errorf("the target did not confirm the upload: %w", err)
	}
	if marker == failed {
		return errors.New("the target could not decode the upload (base64 or disk full)")
	}
	return nil
}

// frames pumps the terminal's frames until the connection ends, in order: the
// tag byte ttyd opens each frame with and its payload. A frame that is not data
// ('0') is one of the server's own — its title, its preferences — which is what
// proves the terminal's process was spawned; input typed before that is dropped.
// yield returns false to stop the pump, which is then not an error.
func (c *ttydCall) frames(ctx context.Context, yield func(tag byte, payload []byte) bool) error {
	for {
		_, reader, err := c.conn.Reader(ctx)
		if err != nil {
			return err
		}
		frame, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		if len(frame) == 0 {
			continue
		}
		if frame[0] != '0' {
			c.markSpawned()
		}
		if !yield(frame[0], frame[1:]) {
			return nil
		}
	}
}

// frameLines is frames with the pty's line discipline put back: the data frames
// are buffered and cut at newlines. A line the connection ended in the middle of
// comes back as leftover, for the caller to treat as the partial row it is;
// leftover is empty when yield stopped the pump itself.
func (c *ttydCall) frameLines(ctx context.Context, yield func(line string) bool) (string, error) {
	var buffered []byte
	stopped := false
	err := c.frames(ctx, func(tag byte, payload []byte) bool {
		if tag != '0' {
			return true
		}
		buffered = append(buffered, payload...)
		for {
			end := bytes.IndexByte(buffered, '\n')
			if end < 0 {
				return true
			}
			line := strings.TrimSuffix(string(buffered[:end]), "\r")
			buffered = buffered[end+1:]
			if !yield(line) {
				stopped = true
				return false
			}
		}
	})
	if stopped || len(buffered) == 0 {
		return "", err
	}
	return strings.TrimSuffix(string(buffered), "\r"), err
}

// pumpFrames reads the terminal's frames and reports every line that ends with
// one of the markers; everything else — the echo of the typed line, the shell's
// prompt, the echoed body — is dropped, so the read side never blocks on
// output nobody wants.
func (c *ttydCall) pumpFrames(ctx context.Context, markers []string, found chan<- string, failure chan<- error) {
	_, err := c.frameLines(ctx, func(line string) bool {
		for _, marker := range markers {
			if !strings.HasSuffix(line, marker) {
				continue
			}
			select {
			case found <- marker:
			case <-ctx.Done():
				return false
			}
		}
		return true
	})
	if err != nil {
		failure <- err
	}
}

// awaitMarker waits for one of the markers the pump reports, the upload
// deadline, or the connection's end.
func awaitMarker(ctx context.Context, found <-chan string, failure <-chan error, deadline time.Time, markers ...string) (string, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		select {
		case marker := <-found:
			for _, want := range markers {
				if marker == want {
					return marker, nil
				}
			}
		case err := <-failure:
			return "", err
		case <-timer.C:
			return "", fmt.Errorf("no answer within %s", ttydUploadWait)
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

// ttydUploadScript is the setup line: raw mode gates the ready marker, so the
// body is only typed once the line discipline can carry it; the body is read
// off the tty (the script's own stdin is the pipeline that decoded this line),
// decoded to the path, and each outcome prints its marker.
func ttydUploadScript(size int, ready, done, failed string) string {
	return strings.Join([]string{
		"stty -icanon -echo min 1 time 0 2>/dev/null || :",
		fmt.Sprintf("printf '%s\\n'", ready),
		fmt.Sprintf("head -c %d | base64 -d > \"$KARMA_UPLOAD\" && chmod 700 \"$KARMA_UPLOAD\" && printf '%s\\n' || printf '%s\\n'",
			size, done, failed),
		"stty icanon echo 2>/dev/null || :",
	}, "\n")
}

// typeBody types the base64 body without a terminator: the tty is in raw mode
// and head(1) reads exactly the bytes the file needs, so nothing may follow.
func (c *ttydCall) typeBody(ctx context.Context, encoded string) error {
	data := []byte(encoded)
	for len(data) > 0 {
		chunk := data
		if len(chunk) > ttydUploadChunk {
			chunk = chunk[:ttydUploadChunk]
		}
		if err := c.conn.Write(ctx, websocket.MessageBinary, append([]byte{'0'}, chunk...)); err != nil {
			return err
		}
		data = data[len(chunk):]
		if len(data) == 0 {
			break
		}
		select {
		case <-time.After(ttydUploadPause):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// probe verifies the channel end to end on one throwaway connection: type one
// base64 round trip and watch it come back. Rejected credentials fail the
// dial; an echo without the payload means the target's base64 is missing; and
// silence means the server drops client input (readonly, or ttyd's command is
// not a shell). The title frame carries ttyd's command line, so the error can
// say what the terminal runs.
func (s *TTYDSession) probe() error {
	ctx, cancel := context.WithTimeout(context.Background(), ttydProbeWindow)
	defer cancel()
	conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	call := &ttydCall{conn: conn, spawned: make(chan struct{})}

	marker := "__KRM_PROBE_" + markerSalt() + "__"
	encoded := base64.StdEncoding.EncodeToString([]byte(marker + "\n"))

	type reply struct{ echo, payload bool }
	replies := make(chan reply, 16)
	titles := make(chan string, 1)
	// The frame pump closes replies when the connection ends, which is what the
	// select below turns into a verdict.
	go func() {
		defer close(replies)
		_ = call.frames(ctx, func(tag byte, payload []byte) bool {
			switch tag {
			case '1':
				select {
				case titles <- string(payload):
				default:
				}
			case '0':
				echoed := bytes.Contains(payload, []byte(encoded))
				select {
				case replies <- reply{echo: echoed, payload: !echoed && bytes.Contains(payload, []byte(marker))}:
				case <-ctx.Done():
					return false
				}
			}
			return true
		})
	}()

	select {
	case <-call.spawned:
	case <-ctx.Done():
		return fmt.Errorf("ttyd at %s started no terminal within %s", s.endpoint, ttydProbeWindow)
	}
	time.Sleep(ttydTypeaheadDelay)
	if err := call.typeLine(ctx, "printf %s "+encoded+" | base64 -d"); err != nil {
		return err
	}

	var echoed, answered bool
	var command string
	verdict := func() error {
		switch {
		case answered:
			return nil
		case echoed:
			return fmt.Errorf("the terminal echoed the probe line but never returned its payload: the target's base64 is missing or broken")
		case command != "":
			return fmt.Errorf("client input got no response (ttyd runs %q): the server drops input — readonly, ttyd from 1.7.4 needs -W/--writable — or the command is not a shell", command)
		default:
			return fmt.Errorf("client input got no response: the server drops input — readonly, ttyd from 1.7.4 needs -W/--writable — or the command is not a shell")
		}
	}
	for {
		select {
		case event, ok := <-replies:
			if !ok {
				return verdict()
			}
			echoed = echoed || event.echo
			if event.payload {
				answered = true
				return nil
			}
		case command = <-titles:
		case <-ctx.Done():
			return verdict()
		}
	}
}

// ttydCall is one websocket connection to a terminal.
type ttydCall struct {
	conn    *websocket.Conn
	spawned chan struct{}
}

// markSpawned closes spawned once, from whichever goroutine sees the first
// initial frame first: the frame pump and the collector both watch for it.
func (c *ttydCall) markSpawned() {
	select {
	case <-c.spawned:
	default:
		close(c.spawned)
	}
}

// collect runs one script over the connection and harvests it with the shared
// timeout machinery: stop is the connection's death, which is also what ends
// the terminal's process on the target.
func (c *ttydCall) collect(ctx context.Context, script string, timeout time.Duration, lineLimit int) model.RunResult {
	marker := markerSalt()
	encoded := base64.StdEncoding.EncodeToString([]byte(ttydPayload(script, marker)))
	line := "printf %s " + encoded + " | base64 -d | /bin/sh"

	lines := make(chan string, 16)
	stopped := make(chan struct{})
	var stopOnce sync.Once
	var exitCode atomic.Int32
	exitCode.Store(-1)
	done := make(chan struct{})
	var errText string

	go func() {
		defer close(done)
		defer close(lines)
		defer c.conn.CloseNow()
		errText = c.readStream(ctx, marker, &exitCode, lines, stopped)
	}()

	select {
	case <-c.spawned:
	case <-time.After(ttydSpawnWait):
	case <-stopped:
	case <-ctx.Done():
	}
	time.Sleep(ttydTypeaheadDelay)
	_ = c.typeLine(ctx, line)

	stop := func() {
		stopOnce.Do(func() {
			close(stopped)
			_ = c.conn.CloseNow()
		})
	}
	return harvestCapped(ctx, source{
		wait: func() { <-done },
		stop: stop,
		readLine: func() (string, bool) {
			return c.nextLine(lines, stopped)
		},
		readAll: func() string {
			// The stderr section precedes the rc marker in the stream, so it
			// is known once the reader ends; harvest's stderr drain waits for
			// exactly that.
			<-done
			return errText
		},
		exitCode: func() int { return int(exitCode.Load()) },
	}, timeout, lineLimit)
}

// nextLine takes one harvested body line, or reports the end of the stream.
// The stopped branch keeps what the reader had already produced before the
// stop.
func (c *ttydCall) nextLine(lines <-chan string, stopped <-chan struct{}) (string, bool) {
	select {
	case line, ok := <-lines:
		return line, ok
	case <-stopped:
		select {
		case line, ok := <-lines:
			return line, ok
		default:
			return "", false
		}
	}
}

// readStream consumes the terminal's frames and cuts the stream into its
// parts: the body between the start marker and the stderr or rc marker, the
// stderr section between its markers, and the exit code from the rc marker.
// The returned string is the stderr text. A partial trailing line is kept
// when the stream ends mid-body, so a connection lost at the end does not
// drop the last row.
func (c *ttydCall) readStream(ctx context.Context, marker string, exitCode *atomic.Int32, lines chan<- string, stopped <-chan struct{}) string {
	start := "__KRM_" + marker + "_S__"
	errBegin := "__KRM_" + marker + "_E__"
	errEnd := "__KRM_" + marker + "_X__"
	rcPrefix := "__KRM_" + marker + "_R_"
	phase := "cut" // cut → body → stderr → tail
	var errText strings.Builder
	emit := func(text string) {
		select {
		case lines <- text + "\n":
		case <-stopped:
		}
	}
	// The rc marker ends its line too: a body without a trailing newline glues
	// in front of it and keeps its shape — the terminator never crossed the pty.
	finish := func(body string, code int) {
		if body != "" {
			select {
			case lines <- body:
			case <-stopped:
			}
		}
		exitCode.Store(int32(code))
	}
	leftover, _ := c.frameLines(ctx, func(line string) bool {
		switch phase {
		case "cut":
			// The marker ends its line; a prompt the shell left unnewline'd may
			// sit in front of it.
			if strings.HasSuffix(line, start) {
				phase = "body"
			}
		case "body":
			if line == errBegin {
				phase = "stderr"
				return true
			}
			if body, code, done := splitTTYDRC(line, rcPrefix); done {
				finish(body, code)
				return false
			}
			emit(line)
		case "stderr":
			if line == errEnd {
				phase = "tail"
				return true
			}
			errText.WriteString(line)
			errText.WriteByte('\n')
		case "tail":
			// Only the rc marker may follow the stderr section.
			if _, code, done := splitTTYDRC(line, rcPrefix); done {
				finish("", code)
				return false
			}
		}
		return true
	})
	if phase == "body" && leftover != "" {
		select {
		case lines <- leftover:
		case <-stopped:
		}
	}
	return errText.String()
}

// splitTTYDRC recognizes the rc marker at the end of a line and returns the
// body text glued in front of it. The marker carries a random token, so its
// shape cannot occur in evidence by accident.
func splitTTYDRC(line, rcPrefix string) (body string, code int, ok bool) {
	at := strings.LastIndex(line, rcPrefix)
	if at < 0 {
		return "", 0, false
	}
	rest := strings.TrimSuffix(line[at+len(rcPrefix):], "__")
	parsed, err := strconv.Atoi(rest)
	if err != nil {
		return "", 0, false
	}
	return line[:at], parsed, true
}

// typeLine sends the line as INPUT in chunks, each chunk its own message: the
// pauses keep each burst the target's tty holds pending under the
// canonical-mode line cap until the shell's line editor drains it.
func (c *ttydCall) typeLine(ctx context.Context, line string) error {
	data := []byte(line + "\n")
	for len(data) > 0 {
		chunk := data
		if len(chunk) > ttydWriteChunk {
			chunk = chunk[:ttydWriteChunk]
		}
		message := append([]byte{'0'}, chunk...)
		if err := c.conn.Write(ctx, websocket.MessageBinary, message); err != nil {
			return err
		}
		data = data[len(chunk):]
		if len(data) == 0 {
			break
		}
		select {
		case <-time.After(ttydChunkPause):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// ttydPayload wraps the collection script for the terminal: a dumb terminal
// so nothing colorizes, the winsize cleared so nothing sizes its tables to
// the terminal (ss pads its columns to the tty width otherwise — ws_col 0 is
// the non-tty layout every tool falls back to), a start marker to cut the
// echoed line and the shell's own chatter away, the script in a subshell so
// its exit does not end the payload shell, stderr captured into a variable
// and replayed as a marked section before the rc marker — the pty merges the
// two streams, and an error line reaching stdout would make a failed tier
// count as an answered one, stopping the fallback chain — and finally the rc
// marker that carries the exit code the pty drops.
func ttydPayload(script, marker string) string {
	return strings.Join([]string{
		"export TERM=dumb",
		"unset COLUMNS",
		"stty cols 0 </dev/tty 2>/dev/null || :",
		"exec 3>&1",
		"printf '__KRM_" + marker + "_S__\\n'",
		"__karma_err=$( ( " + script + " ) 2>&1 1>&3 3>&- ); __karma_rc=$?",
		"if [ -n \"$__karma_err\" ]; then printf '__KRM_" + marker + "_E__\\n'; printf '%s\\n' \"$__karma_err\"; printf '__KRM_" + marker + "_X__\\n'; fi",
		"printf '__KRM_" + marker + "_R_%d__\\n' \"$__karma_rc\"",
	}, "\n")
}

// markerSalt is the per-call marker salt: crypto/rand.Text's base32 alphabet
// carries no character a shell, printf or the marker match reads, and its 128
// bits keep two runs' markers apart.
func markerSalt() string { return rand.Text() }

// insecureTLS accepts any server certificate: the ws:// form already carries
// everything in the clear, this only says so for wss.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

// pinnedTLS verifies the leaf certificate's SHA-256 against the fingerprint
// instead of the chain: the self-signed answer. InsecureSkipVerify is set
// because the pin itself is the verification.
func pinnedTLS(fingerprint [sha256.Size]byte) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				if sha256.Sum256(raw) == fingerprint {
					return nil
				}
			}
			return fmt.Errorf("no certificate in the chain matches the pinned fingerprint")
		},
	}
}
