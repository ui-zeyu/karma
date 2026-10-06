// Package session is the execution channel layer: it turns the catalog's
// invocations into runs on a target. Two channels implement it — local
// subprocesses (local.go) and one SSH connection (ssh.go) — and the rest of
// karma depends only on the interfaces declared here.
//
// Every run is harvested the same way (harvest.go): the reads are attached
// first, a timeout or a cancel (Ctrl-C) stops the data source rather than the
// reads, output already produced is kept, and a line limit stops the source
// once enough rows exist.
package session

import (
	"context"
	"io"
	"time"

	"karma/internal/model"
)

// Session is one established channel. Runner talks to this interface alone, so
// adding a channel on the same platform means implementing another Session.
type Session interface {
	// Name is the channel's display name in the report header ("local", "ssh").
	Name() string
	// Channel is which side of the wire karma runs on: the runner resolves
	// each probe tier against it while walking the chain.
	Channel() model.Channel
	// Run executes one invocation, with a per-command timeout and an optional
	// line limit, and harvests its output. A timeout of zero or less is no
	// deadline; a cancelled context stops the data source and keeps the output
	// already produced.
	Run(ctx context.Context, inv model.Invocation, timeout time.Duration, lineLimit int) model.RunResult
	// Close releases the channel's resources.
	Close() error
}

// Transport is the channel factory: a successful Open returns a usable Session.
// The display name and the channel live on the Session alone — the report
// header and the chain resolution start only after a connection exists.
type Transport interface {
	Platform() model.Platform
	Open() (Session, error)
}

// Uploader is a channel that can write a file to the target. The bootstrap mode
// ships karma's own binary over it and runs it there, so the target's kernel
// interfaces are read without a shell, coreutils or a hooked libc in between.
// content is the complete file: an upload either arrives whole or fails.
type Uploader interface {
	Upload(ctx context.Context, path string, content []byte) error
}

// Streamer is a channel that can run one invocation with its output passed
// through as it arrives. Bootstrap needs it: the target runs its own karma,
// which renders its own report, so the outer process hands the bytes to the
// terminal instead of harvesting and re-rendering them. The exit code is the
// remote command's, or -1 when the channel could not report one.
type Streamer interface {
	Stream(ctx context.Context, inv model.Invocation, out, errOut io.Writer) (int, error)
}
