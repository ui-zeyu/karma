package facts

import (
	"context"
	"fmt"
	"testing"
	"time"

	"karma/internal/model"
)

// gather writes each job's own slice slot from its goroutine and assembles the
// map after the join, so every result must arrive keyed by its own job name.
func TestGatherKeysEachResultByItsJobName(t *testing.T) {
	jobs := make(map[string]func(context.Context) model.RunResult)
	for i := range 32 {
		name := fmt.Sprintf("job%02d", i)
		jobs[name] = func(context.Context) model.RunResult {
			time.Sleep(time.Millisecond)
			return model.RunResult{Verdict: model.VerdictAnswered, Stdout: name}
		}
	}
	results := gather(context.Background(), jobs)
	if len(results) != len(jobs) {
		t.Fatalf("every job should land in the map: got %d of %d", len(results), len(jobs))
	}
	for name, result := range results {
		if result.Stdout != name {
			t.Fatalf("a result drifted to the wrong key: %s carries %q", name, result.Stdout)
		}
	}
}
