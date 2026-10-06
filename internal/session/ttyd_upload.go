// The ttyd channel's upload path: the bootstrap mode types a binary into the
// terminal, and the pty gives it neither an exit status nor a way to tell the
// typed body from the echo, so the conversation is markers in, markers out.

package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/coder/websocket"

	"karma/internal/script"
)

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
	if err := sleepCtx(ctx, ttydTypeaheadDelay); err != nil {
		return err
	}
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
		if err := sleepCtx(ctx, ttydUploadPause); err != nil {
			return err
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
