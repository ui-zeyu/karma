// Presentation damage: the render loop is karma's own goroutine, so a panic in it
// has no recover above it — it would end the report where the contract is that one
// broken panel is one broken panel. And a check whose result never arrived must not
// hold every panel behind it: the catalog order is released by index, so a lost
// event would otherwise stall the whole tail of the report.

package render

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"karma/internal/model"
)

func TestLiveObserverReportsDamageAndKeepsTheOrderMoving(t *testing.T) {
	var buf bytes.Buffer
	first := &model.Check{ID: "listen", Aspect: model.AspectNetwork}
	second := &model.Check{ID: "users", Aspect: model.AspectIdentity}
	observer := NewLiveObserver(&buf, []*model.Check{first, second}, 40, 48, false)
	observer.Start()
	// The result of "listen" never arrives: the callback that would have carried
	// it is the one that broke.
	observer.Damaged(first, errors.New("panel blew up"))
	observer.CheckFinished(second, &model.CheckResult{
		Check:   second,
		Outcome: model.Collected,
		Document: model.Document{Sections: []model.Section{{
			Lines: []model.Line{{Text: "root:x:0:0", Severity: model.Info}},
		}}},
	})
	observer.Close()

	out := buf.String()
	if !strings.Contains(out, "listen") || !strings.Contains(out, "panel blew up") {
		t.Fatalf("the reader should be told what the run lost: %q", out)
	}
	if !strings.Contains(out, "root:x:0:0") || !strings.Contains(out, "USERS") {
		t.Fatalf("the panel after the lost one should still be released: %q", out)
	}
}

// A panic inside one frame is reported and the loop keeps drawing: the checks
// still queued get their panels.
func TestLiveObserverSurvivesAPanickingPanel(t *testing.T) {
	var buf bytes.Buffer
	check := &model.Check{ID: "listen", Aspect: model.AspectNetwork}
	observer := NewLiveObserver(&buf, []*model.Check{check}, 40, 48, false)
	original := panelRenderer
	panelRenderer = func(*model.CheckResult, int, int) string { panic("layout blew up") }
	t.Cleanup(func() { panelRenderer = original })

	observer.Start()
	observer.CheckStarted(check)
	observer.CheckFinished(check, &model.CheckResult{Check: check, Outcome: model.Collected, Raw: "rows\n"})
	observer.Close()

	out := buf.String()
	if !strings.Contains(out, "LISTEN") || !strings.Contains(out, "rows") {
		t.Fatalf("a broken layout should fall back to the raw text: %q", out)
	}
}
