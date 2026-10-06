// Signal handling for one run.
//
// The first SIGINT or SIGTERM cancels the run's context: collection stops
// promptly, in-flight checks keep the output they had already read, and the
// partial report is still presented. A second signal exits at once — a channel
// operation the context cannot break (an uninterruptible syscall on the target,
// a library call with no context) would otherwise leave the operator with no way
// to stop karma short of SIGKILL.

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// interruptible returns the run's context and the cleanup that ends its interest
// in signals. Call the cleanup once the run is over.
func interruptible() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 2)
	finished := make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	var once sync.Once
	go func() {
		select {
		case <-signals:
			cancel()
		case <-finished:
			return
		}
		select {
		case got := <-signals:
			// The operator asked twice: nothing between here and the exit is
			// worth the wait, and the report already holds what it has.
			fmt.Fprintf(os.Stderr, "karma: %v again, exiting now\n", got)
			os.Exit(int(ExitInterrupted))
		case <-finished:
		}
	}()
	return ctx, func() {
		once.Do(func() {
			signal.Stop(signals)
			close(finished)
			cancel()
		})
	}
}
