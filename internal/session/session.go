// Package session is the execution channel layer: it turns the catalog's
// invocations into runs on a target. Three channels implement it — local
// subprocesses (local.go), one SSH connection (ssh_session.go), and a ttyd
// websocket terminal (ttyd_session.go) — and the rest of karma depends only on
// the interfaces declared here.
//
// Every run is harvested the same way (harvest.go): the reads are attached
// first, the deadline or a cancel (Ctrl-C) stops the data source rather than the
// reads, output already produced is kept, and a row cap stops the source once
// enough rows exist. One finished call is read into a model.Verdict there, so
// the chain above reads outcomes rather than exit codes. The deadline is the
// context's, which is what puts the channel's own setup — a dial, a session
// open, an exec — inside the same bound as the output.
package session

import (
	"context"
	"time"

	"karma/internal/model"
)

// Session is one established channel. Runner talks to this interface alone, so
// adding a channel on the same platform means implementing another Session.
type Session interface {
	// Name is the channel's short display name ("local", "ssh", "ttyd"); the
	// saved bundle's manifest records it.
	Name() string
	// Describe is the channel and what it reaches, as the report header names
	// it: "local", "ssh root@host:22", "ttyd ws://host:7681/ws". Credentials
	// are never part of it.
	Describe() string
	// Channel is which side of the wire karma runs on: the runner resolves
	// each probe tier against it while walking the chain.
	Channel() model.Channel
	// Run executes one call and harvests its output into a model.RunResult
	// whose Verdict says what happened. The context bounds the whole call — the
	// channel's own setup, the command, and the output — so a caller states a
	// deadline with Within; a cancelled context stops the data source and keeps
	// the output already produced.
	Run(ctx context.Context, call model.Call) model.RunResult
	// Close releases the channel's resources.
	Close() error
}

// Transport is the channel factory: a successful Open returns a usable Session.
// The display name and the channel live on the Session alone — the report
// header and the chain resolution start only after a connection exists.
type Transport interface {
	Platform() model.Platform
	// Open connects, under the run's own context: Ctrl-C must end a dial or a
	// handshake, and one is not interruptible through the channel it has not
	// finished opening.
	Open(ctx context.Context) (Session, error)
}

// Within bounds one call or one walk by budget, and returns the context alone
// when budget is zero or less: the deadline travels in the context, so it is
// stated once, where the policy lives — one check's walk in the runner, one
// host fact or one bootstrap command in the command line — and every layer
// below it inherits the same one.
func Within(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	if budget <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, budget)
}

// Uploader is a channel that can write one file to the target. The bootstrap
// mode ships karma's own binary over it, so the operator can run it there and
// read the kernel's interfaces in process — no shell, coreutils or hooked libc
// in the path. content is the complete file: an upload either arrives whole or
// fails.
type Uploader interface {
	Upload(ctx context.Context, path string, content []byte) error
}

// LostChannel is the capability of a session whose transport can die under it:
// Lost reports whether that already happened — every further call would fail
// the same way. The runner stops queueing checks then, and the command line
// says so once, instead of one identical failure panel per remaining check.
type LostChannel interface {
	Lost() bool
}

// Delegator is the capability of a remote session that collects through a karma
// binary placed on the target: UseCollector names it, and every call that names
// a catalog tier after that is one probe of that binary — run there, in process
// — instead of the invocation run here. Collector is empty until one is named,
// and a session that is not given one runs the invocation itself.
//
// It is a capability rather than a method on Session because placement happens
// after the connection exists (the target has to answer uname first) and because
// a channel that cannot carry an upload never has one.
type Delegator interface {
	UseCollector(path string)
	Collector() string
}
