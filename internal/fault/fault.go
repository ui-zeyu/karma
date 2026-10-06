// Package fault turns a panic into a value.
//
// A panic on a goroutine has no recover above it: it ends the process and takes
// the whole report with it, where karma's contract is that one broken piece
// fails alone. Every boundary a run crosses — a check's walk, a channel's
// reader, the render loop, one in-process body, one channel setup — goes
// through here, so the wording, the stack, and the decision to keep one are a
// single package's business instead of one recover per call site.
//
// The boundary names the piece that broke ("check ssh-authorized-keys", "ttyd
// frame pump"); the report prints the message, and a saved bundle keeps the
// stack, which is what makes an internal error actionable after the fact.
package fault

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// Panic is one recovered panic.
type Panic struct {
	// Boundary is the piece that broke, as the report names it.
	Boundary string
	// Value is what the panic carried.
	Value any
	// Stack is the goroutine's stack at the recover point, innermost frame
	// first. It is what tells a report reader where in karma the defect is.
	Stack []byte
}

// New captures a recovered panic value as a *Panic. It is for the recover sites
// that live outside Catch (a deferred recover of the caller's own), so a panic
// can never be recorded in a shape of its own.
func New(boundary string, value any) *Panic {
	return &Panic{Boundary: boundary, Value: value, Stack: debug.Stack()}
}

// Error is the one line a panel note or a stderr report shows.
func (p *Panic) Error() string {
	return fmt.Sprintf("internal error in %s: %v", p.Boundary, p.Value)
}

// Detail is the full account for a saved bundle: the message, then the stack.
func (p *Panic) Detail() string {
	var out strings.Builder
	out.WriteString(p.Error())
	out.WriteString("\n")
	out.Write(p.Stack)
	return out.String()
}

// Catch runs one boundary and turns a panic into a *Panic error. The value fn
// returns comes back unchanged, nil included, so a caller can wrap an existing
// step without changing what it reports.
func Catch(boundary string, fn func() error) (err error) {
	defer func() {
		if problem := recover(); problem != nil {
			err = New(boundary, problem)
		}
	}()
	return fn()
}

// Result runs one boundary that produces a value. A panic comes back as the
// zero value plus a *Panic error.
func Result[T any](boundary string, fn func() T) (value T, err error) {
	defer func() {
		if problem := recover(); problem != nil {
			var zero T
			value, err = zero, New(boundary, problem)
		}
	}()
	return fn(), nil
}
