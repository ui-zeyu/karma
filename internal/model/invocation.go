// Invocation: how a call gets its shell text.

package model

// Invocation is one way a call gets its text. Shell is the only kind: the audit
// reads the target through scripts it sends, and its native bodies run in
// process without crossing a channel.
type Invocation interface {
	isInvocation()
}

// Shell is a script handed to /bin/sh -c.
type Shell struct{ Script string }

func (Shell) isInvocation() {}
