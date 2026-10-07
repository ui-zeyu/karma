// A call's budget reaches the ttyd channel's own setup: the wait for the
// terminal to spawn and the pause before the line is typed. A server that
// accepts the websocket and never spawns must end with that budget.

package session

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"

	"karma/internal/model"
)

// silentTTYD accepts the websocket and never sends a frame.
func newSilentTTYD(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"tty"}})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			if _, _, err := conn.Reader(r.Context()); err != nil {
				return
			}
		}
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return "ws://" + listener.Addr().String() + "/ws"
}

func TestTTYDSetupIsBoundedByTheCallBudget(t *testing.T) {
	sess := &TTYDSession{endpoint: newSilentTTYD(t)}
	budget := 300 * time.Millisecond
	started := time.Now()
	result := runCall(context.Background(), sess, model.Shell{Script: "echo hi"}, budget, model.RowCap{})
	elapsed := time.Since(started)
	if result.Verdict != model.VerdictTimedOut {
		t.Fatalf("a setup that outlives the budget is this call's deadline: %+v", result)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("the call took %s for a %s budget: the setup is outside the deadline", elapsed, budget)
	}
}
