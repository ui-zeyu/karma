// Package fault turns a panic into a value.
//
// A panic on a goroutine has no recover above it: it ends the process and takes
// the whole report with it, where karma's contract is that one broken piece
// fails alone. Every boundary a run crosses — a collection, a watcher reader,
// the report loop — goes through here, so the wording, the stack, and the
// decision to keep one are a single package's business instead of one recover
// per call site.
//
// The boundary names the piece that broke ("collection", "watch source");
// the report prints the message, and the value keeps the stack it was recovered
// at, which is what a test or a debugger reads to find the frame.
package fault

import (
	"fmt"
	"runtime/debug"
)

// Panic is one recovered panic.
type Panic struct {
	// Boundary is the piece that broke, as the report names it.
	Boundary string
	// Value is what the panic carried.
	Value any
	// Stack is the goroutine's stack at the recover point, innermost frame
	// first. The report prints the message alone, so this is kept for a test or
	// a debugger that has to name the frame.
	Stack []byte
}

// newPanic captures a recovered panic value as a *Panic. Catch is the one
// recover site, so a panic is never recorded in a shape of its own.
func newPanic(boundary string, value any) *Panic {
	return &Panic{Boundary: boundary, Value: value, Stack: debug.Stack()}
}

// Error is the one line a panel note or a stderr report shows.
func (p *Panic) Error() string {
	return fmt.Sprintf("internal error in %s: %v", p.Boundary, p.Value)
}

// Catch runs one boundary and turns a panic into a *Panic error. The value fn
// returns comes back unchanged, nil included, so a caller can wrap an existing
// step without changing what it reports.
func Catch(boundary string, fn func() error) (err error) {
	defer func() {
		if problem := recover(); problem != nil {
			err = newPanic(boundary, problem)
		}
	}()
	return fn()
}
