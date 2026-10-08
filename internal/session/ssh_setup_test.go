// A call's budget reaches the channel's own setup, not only the harvest. The
// ssh library's session open and exec request take no context, so they run
// under session.setup: a server that accepts and then stops answering ends
// with the deadline, and the transport is latched lost.

package session

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"karma/internal/model"
)

// silentSSHD accepts the session channel and swallows every request: the shape
// of a server that is still holding the connection but no longer answering.
type silentSSHD struct {
	listener net.Listener
	// pace is handed to the transport this fake opens: a test that states a
	// bound in milliseconds sets it here (see pace).
	pace pace
}

func newSilentSSHD(t *testing.T) *silentSSHD {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate the host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(requests)
				for newChannel := range channels {
					channel, channelRequests, err := newChannel.Accept()
					if err != nil {
						continue
					}
					_ = channel
					go func() {
						// Swallowed: no reply to the exec request, ever.
						for range channelRequests {
						}
					}()
				}
			}()
		}
	}()
	return &silentSSHD{listener: listener}
}

func (f *silentSSHD) open(t *testing.T) *SSHSession {
	t.Helper()
	host, portText, err := net.SplitHostPort(f.listener.Addr().String())
	if err != nil {
		t.Fatalf("split the listener address: %v", err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatalf("read the listener port: %v", err)
	}
	sess, err := (&SSHTransport{
		pace:        f.pace,
		Destination: SSHDestination{Host: host, Port: port},
		HostKey:     HostKeyNo,
		Password:    "unused: the fake server authenticates nobody",
	}).Open(t.Context())
	if err != nil {
		t.Fatalf("open the channel: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess.(*SSHSession)
}

func TestSSHSetupIsBoundedByTheCallBudget(t *testing.T) {
	t.Parallel()
	sess := newSilentSSHD(t).open(t)
	budget := 300 * time.Millisecond
	started := time.Now()
	result := runCall(t.Context(), sess, model.NewCommand("id"), budget, model.RowCap{})
	elapsed := time.Since(started)
	if result.Verdict != model.VerdictTimedOut {
		t.Fatalf("a setup that outlives the budget is this call's deadline: %+v", result)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("the call took %s for a %s budget", elapsed, budget)
	}
}

// The other half of the rule: a setup that outlives the library's own bound means
// the transport stopped answering, so the channel is latched lost — which is what
// stops the runner from queueing the checks it would all fail — instead of
// waiting for the next call to find out.
func TestSSHUnansweredSetupLatchesTheChannelLost(t *testing.T) {
	t.Parallel()
	silent := newSilentSSHD(t)
	// The transport bound, not the call's: the goal is the channel deciding that
	// a server past this bound stopped answering.
	silent.pace = pace{sshSetup: 50 * time.Millisecond}
	sess := silent.open(t)
	if sess.Lost() {
		t.Fatal("a fresh connection is not lost")
	}
	result := runCall(t.Context(), sess, model.NewCommand("id"), time.Minute, model.RowCap{})
	if result.Verdict != model.VerdictFailed {
		t.Fatalf("an unanswered setup is this call failing: %+v", result)
	}
	if !sess.Lost() {
		t.Fatal("a transport that stopped answering should be latched lost")
	}
}
