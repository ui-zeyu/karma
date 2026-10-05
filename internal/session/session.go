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
	"time"

	"karma/internal/model"
)

// Session is one established channel. Runner talks to this interface alone, so
// adding a channel on the same platform means implementing another Session.
type Session interface {
	// Name is the channel's display name in the report header ("local", "ssh").
	Name() string
	// Run executes one invocation, with a per-command timeout and an optional
	// line limit, and harvests its output. A cancelled context stops the data
	// source and keeps the output already produced.
	Run(ctx context.Context, inv model.Invocation, timeout time.Duration, lineLimit int) model.RunResult
	// Close releases the channel's resources.
	Close() error
}

// Transport is the channel factory: a successful Open returns a usable Session.
type Transport interface {
	Name() string
	Platform() model.Platform
	Open() (Session, error)
}
