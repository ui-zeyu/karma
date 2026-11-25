// Package session is the execution channel layer: it sends one shell script to
// a target and harvests the answer. Three channels implement it — local
// subprocesses, one SSH connection, and a ttyd websocket terminal — and the
// audit depends only on the interfaces declared here.
//
// Every call is harvested the same way: the reads are attached first, the
// deadline or a cancel (Ctrl-C) stops the data source rather than the reads,
// output already produced is kept, and a byte valve bounds the body. One
// finished call is read into a model.RunResult there, so the layer above reads
// outcomes rather than exit codes. The deadline is the context's, which puts
// the channel's own setup — a dial, a session open, an exec — inside the same
// bound as the output.
package session

import (
	"context"
	"time"

	"karma/internal/model"
)

// Session is one established channel.
type Session interface {
	// Name is the channel's short display name ("local", "ssh", "ttyd").
	Name() string
	// Run executes one script and harvests its output. The context bounds the
	// whole call — the channel's own setup, the command, and the output — so a
	// caller states a deadline with Within; a cancelled context stops the data
	// source and keeps the output already produced.
	Run(ctx context.Context, call model.Call) model.RunResult
	// Close releases the channel's resources.
	Close() error
}

// Transport is the channel factory: a successful Open returns a usable Session.
type Transport interface {
	// Open connects under the run's own context: Ctrl-C must end a dial or a
	// handshake, and one is not interruptible through the channel it has not
	// finished opening.
	Open(ctx context.Context) (Session, error)
}

// Within bounds one collection by budget; a zero or negative budget leaves the
// context alone.
func Within(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	if budget <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, budget)
}

// Uploader is a channel that can write one file to the target. The bootstrap
// mode ships karma's own binary over it, so the operator can run it there and
// read the kernel's interfaces in process.
type Uploader interface {
	Upload(ctx context.Context, path string, content []byte) error
}

// LostChannel is the capability of a session whose transport can die under it:
// Lost reports whether that already happened. The command line then says so
// once instead of sending the remaining scripts into the same failure.
type LostChannel interface {
	Lost() bool
}
