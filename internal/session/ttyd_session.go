// TTYDSession: the ttyd channel's run path. One websocket connection per
// call, one typed line per call, the body cut out between markers, the exit
// code read from the rc marker — the pty merges the streams and drops the
// numeric exit status, so the payload puts both back.

package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"karma/internal/fault"
	"karma/internal/model"
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
	lost     atomic.Bool
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

// Lost reports whether the endpoint can no longer be dialled — the server or
// the network to it died. Latched on the first failed dial that was not this
// run's own cancellation, since every later call would fail the same way.
func (s *TTYDSession) Lost() bool { return s.lost.Load() }

// Close releases the channel's resources: connections live per call.
func (s *TTYDSession) Close() error { return nil }

// Run types one collection line into a fresh terminal and harvests the answer.
func (s *TTYDSession) Run(ctx context.Context, call model.Call) model.RunResult {
	conn, err := s.connect(ctx)
	if err != nil {
		// The endpoint is gone unless the failure is our own cancellation:
		// Ctrl-C is the operator ending the run, and every later dial would
		// fail for that reason alone.
		if ctx.Err() == nil {
			s.lost.Store(true)
		}
		return model.RunResult{Verdict: model.VerdictFailed, Stderr: fmt.Sprintf("ttyd channel error: %v", err), ExitCode: -1}
	}
	terminal := &ttydCall{conn: conn, spawned: make(chan struct{})}
	return terminal.collect(ctx, mustShellText(call.Inv), call.Cap)
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

// probe verifies the endpoint end to end on one throwaway connection. It runs
// under the run's context, so Ctrl-C ends it like every other step.
func (s *TTYDSession) probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, ttydProbeWindow)
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
	// select below turns into a verdict. The reports below are not read after
	// the close: the select's verdict is the answer either way.
	var damaged atomic.Pointer[error]
	go func() {
		defer close(replies)
		if err := fault.Catch("ttyd frame pump", func() error {
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
			return nil
		}); err != nil {
			damaged.Store(&err)
		}
	}()

	select {
	case <-call.spawned:
	case <-ctx.Done():
		return fmt.Errorf("ttyd at %s started no terminal within %s", s.endpoint, ttydProbeWindow)
	}
	if err := sleepCtx(ctx, ttydTypeaheadDelay); err != nil {
		return err
	}
	if err := call.typeLine(ctx, "printf %s "+encoded+" | base64 -d"); err != nil {
		return err
	}

	var echoed, answered bool
	var command string
	verdict := func() error {
		if problem := damaged.Load(); problem != nil {
			return fmt.Errorf("the ttyd frame pump failed: %w", *problem)
		}
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
// the terminal's process on the target. The wait for the terminal to spawn and
// the pause before typing belong to the call's deadline like everything else —
// they are the channel's own setup.
func (c *ttydCall) collect(ctx context.Context, script string, cap model.RowCap) model.RunResult {
	marker := markerSalt()
	encoded := base64.StdEncoding.EncodeToString([]byte(ttydPayload(script, marker)))
	line := "printf %s " + encoded + " | base64 -d | /bin/sh"

	stream := &ttydStream{
		conn:    c.conn,
		lines:   make(chan string, 16),
		stopped: make(chan struct{}),
		done:    make(chan struct{}),
	}
	stream.code.Store(-1)
	stream.read(ctx, c, marker)

	select {
	case <-c.spawned:
	case <-time.After(ttydSpawnWait):
	case <-stream.stopped:
	case <-ctx.Done():
	}
	if err := sleepCtx(ctx, ttydTypeaheadDelay); err != nil {
		stream.stop()
		return model.RunResult{Verdict: cutVerdict(ctx), ExitCode: -1}
	}
	if err := c.typeLine(ctx, line); err != nil {
		// The line never went out, so there is nothing to harvest: the cut is
		// the call's own deadline or cancel, and anything else is this
		// connection failing.
		stream.stop()
		if ctx.Err() != nil {
			return model.RunResult{Verdict: cutVerdict(ctx), ExitCode: -1}
		}
		return model.RunResult{Verdict: model.VerdictFailed, Stderr: fmt.Sprintf("ttyd channel error: %v", err), ExitCode: -1}
	}
	return harvest(ctx, stream, cap)
}

// sleepCtx is one of the channel's own pacing waits, ended early by the call's
// context: the pty's line discipline needs a moment before a typed line, and
// that moment is part of the call's budget.
func sleepCtx(ctx context.Context, pause time.Duration) error {
	timer := time.NewTimer(pause)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ttydStream is one collection over a websocket connection as harvest's data
// source. One reader goroutine cuts the terminal's frames into body lines; stop
// is the connection's death, which is also what ends the terminal's process on
// the target.
type ttydStream struct {
	baseSource
	conn     *websocket.Conn
	lines    chan string
	stopped  chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	code     atomic.Int32
	// stderr is the stderr section the reader cut out of the stream; it is
	// written by the reader goroutine and read after done.
	stderr string
}

// read starts the reader. The panic barrier records a reader that died
// mid-stream before done is closed, so the call's own result paths see the
// reason: it is not known to have read everything.
func (s *ttydStream) read(ctx context.Context, call *ttydCall, marker string) {
	go func() {
		defer close(s.done)
		defer close(s.lines)
		defer s.conn.CloseNow()
		if err := fault.Catch("ttyd reader", func() error {
			s.stderr = s.readStream(ctx, call, marker)
			return nil
		}); err != nil {
			s.stderr = err.Error() + "\n"
		}
	}()
}

func (s *ttydStream) wait() { <-s.done }

func (s *ttydStream) stop() {
	s.stopOnce.Do(func() {
		close(s.stopped)
		_ = s.conn.CloseNow()
	})
}

func (s *ttydStream) readLine() (string, bool) { return s.nextLine() }

func (s *ttydStream) readAll() string {
	// The stderr section precedes the rc marker in the stream, so it is known
	// once the reader ends; harvest's stderr drain waits for exactly that.
	<-s.done
	return s.stderr
}

func (s *ttydStream) exitCode() int { return int(s.code.Load()) }

// nextLine takes one harvested body line, or reports the end of the stream.
// The stopped branch keeps what the reader had already produced before the
// stop.
func (s *ttydStream) nextLine() (string, bool) {
	select {
	case line, ok := <-s.lines:
		return line, ok
	case <-s.stopped:
		select {
		case line, ok := <-s.lines:
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
func (s *ttydStream) readStream(ctx context.Context, call *ttydCall, marker string) string {
	start := "__KRM_" + marker + "_S__"
	errBegin := "__KRM_" + marker + "_E__"
	errEnd := "__KRM_" + marker + "_X__"
	rcPrefix := "__KRM_" + marker + "_R_"
	phase := "cut" // cut → body → stderr → tail
	var errText strings.Builder
	emit := func(text string) {
		select {
		case s.lines <- text + "\n":
		case <-s.stopped:
		}
	}
	// The rc marker ends its line too: a body without a trailing newline glues
	// in front of it and keeps its shape — the terminator never crossed the pty.
	finish := func(body string, code int) {
		if body != "" {
			select {
			case s.lines <- body:
			case <-s.stopped:
			}
		}
		s.code.Store(int32(code))
	}
	leftover, _ := call.frameLines(ctx, func(line string) bool {
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
		case s.lines <- leftover:
		case <-s.stopped:
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
		if err := sleepCtx(ctx, ttydChunkPause); err != nil {
			return err
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
