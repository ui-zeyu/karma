package audit

// The collectors' one bounded-worker loop. Hashing, the package sweep and the
// pid sweep share it, so the worker math and the cancellation rule live in
// exactly one place.

import (
	"context"
	"runtime"
	"sync"
)

// workerCount scales a pool to the host and the job's weight per item: an
// I/O-heavy hash pass stays narrow, a kill(0) sweep goes wide. The caps keep
// a small host from oversubscribing and a large one from overthreading.
func workerCount(weight int) int {
	return min(max(runtime.GOMAXPROCS(0)*weight, 2), 32)
}

// each runs fn(worker, i) for i in [0, n) across a bounded pool. Results go
// to the per-worker slot the first argument names, so the hot loop holds no
// lock; a canceled context stops the workers between items.
func each(ctx context.Context, n, workers int, fn func(worker, i int)) {
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < n; i += workers {
				if ctx != nil && ctx.Err() != nil {
					return
				}
				fn(w, i)
			}
		}(w)
	}
	wg.Wait()
}
