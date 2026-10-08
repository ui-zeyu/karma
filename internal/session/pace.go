// Pace is what a channel waits for beyond the call's own deadline: the grace a
// source stopped on purpose gets before the harvest keeps what arrived, the
// grace an in-process body already unwinding gets to hand its partial answer
// back, one ssh setup step before the transport reads as unanswered, the close
// of a connection, an upload the target stopped draining, and (ttyd) the dial
// and the open-time probe.
//
// The call's budget is the operator's and travels in the context (Within); these
// bounds are the channel's own, so they live on the channel. That is what lets a
// test build a channel whose bounds are milliseconds — the behavior it states is
// the same, only the waiting is not — and let the tests of one channel run
// beside each other.

package session

import (
	"cmp"
	"time"
)

// pace holds those bounds. The zero value is the shipped waiting: resolved
// states every unset bound, so a channel built with no pace behaves like one
// built with the defaults, and a test states only the bound it wants shorter.
type pace struct {
	cutGrace    time.Duration
	bodyGrace   time.Duration
	sshSetup    time.Duration
	sshClose    time.Duration
	uploadStall time.Duration
	ttydDial    time.Duration
	ttydProbe   time.Duration
}

// resolved fills every unset bound with the shipped one. Each number bounds a
// different wait, so they are stated together here and nowhere else.
func (p pace) resolved() pace {
	return pace{
		// A stopped source that outlives this could not be stopped; the harvest
		// keeps what the reads already had and says so.
		cutGrace: cmp.Or(p.cutGrace, time.Second),
		// A body parked in a syscall never observes a cancel; a body that is
		// unwinding (every walk checks the context) gets this long to hand back
		// what it read.
		bodyGrace: cmp.Or(p.bodyGrace, 250*time.Millisecond),
		// A healthy server answers a dial, a handshake, a session open and an
		// exec request each in milliseconds, so one bound says the same thing
		// about all of them: past it, the transport stopped answering.
		sshSetup: cmp.Or(p.sshSetup, 30*time.Second),
		// A hung Close must not stall the whole collection on teardown.
		sshClose: cmp.Or(p.sshClose, 5*time.Second),
		// The gap between two chunks of an upload; a target that stops draining
		// would block a Write forever.
		uploadStall: cmp.Or(p.uploadStall, 60*time.Second),
		ttydDial:    cmp.Or(p.ttydDial, 15*time.Second),
		// The open-time probe: a broken endpoint fails once here rather than
		// silently in every check.
		ttydProbe: cmp.Or(p.ttydProbe, 10*time.Second),
	}
}
