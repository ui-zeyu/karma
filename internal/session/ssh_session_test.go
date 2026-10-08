package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"karma/internal/model"
)

func TestCommandExitCode(t *testing.T) {
	t.Parallel()
	if got := commandExitCode(nil); got != 0 {
		t.Fatalf("Wait returning nil means remote exit code 0, got %d", got)
	}
	if got := commandExitCode(&ssh.ExitError{}); got != 0 {
		t.Fatalf("ExitError should read the status word, whose zero value is 0, got %d", got)
	}
	if got := commandExitCode(errors.New("connection lost")); got != -1 {
		t.Fatalf("with no exit status it should be -1, got %d", got)
	}
}

// fakeSSHD is the server side of one connection: no authentication, and every
// session channel refused with the server's own reason — what an sshd at its
// MaxSessions limit answers. disconnect closes the transport under the client.
type fakeSSHD struct {
	listener net.Listener
	server   chan *ssh.ServerConn
	// pace is handed to the transport this fake opens: a test that states a
	// bound in milliseconds sets it here (see pace).
	pace pace
}

func newFakeSSHD(t *testing.T) *fakeSSHD {
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
	fake := &fakeSSHD{listener: listener, server: make(chan *ssh.ServerConn, 4)}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				continue
			}
			fake.server <- server
			go ssh.DiscardRequests(reqs)
			go func() {
				for newChannel := range chans {
					_ = newChannel.Reject(ssh.Prohibited, "the server is at its session limit")
				}
			}()
		}
	}()
	return fake
}

func (f *fakeSSHD) open(t *testing.T) *SSHSession {
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
		Destination: SSHDestination{Host: host, Port: port},
		HostKey:     HostKeyNo,
		Password:    "unused: the fake server authenticates nobody",
		pace:        f.pace,
	}).Open(context.Background())
	if err != nil {
		t.Fatalf("open the channel: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess.(*SSHSession)
}

// disconnect closes the transport under the client, the way a dropped network
// or a restarting sshd does.
func (f *fakeSSHD) disconnect(t *testing.T) {
	t.Helper()
	select {
	case server := <-f.server:
		_ = server.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no connection was accepted")
	}
}

// A refusal is the server answering, not the transport dying: the connection
// survives it, so the run keeps collecting the checks still queued.
func TestSSHRefusedChannelDoesNotLoseTheConnection(t *testing.T) {
	t.Parallel()
	fake := newFakeSSHD(t)
	sess := fake.open(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	result := runCall(ctx, sess,
		model.NewCommand("id"), 5*time.Second, model.RowCap{})
	if result.Verdict != model.VerdictFailed || !strings.Contains(result.Stderr, "the server is at its session limit") {
		t.Fatalf("a refused channel should fail that one call, got %+v", result)
	}
	if sess.Lost() {
		t.Fatal("the server refused one channel; the connection is still answering")
	}
}

// The other half: a transport that goes away is latched, which is what stops
// the runner from queueing the checks it would all fail.
func TestSSHDisconnectedTransportIsLost(t *testing.T) {
	t.Parallel()
	fake := newFakeSSHD(t)
	sess := fake.open(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	fake.disconnect(t)

	deadline := time.Now().Add(10 * time.Second)
	for !sess.Lost() && time.Now().Before(deadline) {
		runCall(ctx, sess,
			model.NewCommand("id"), time.Second, model.RowCap{})
		time.Sleep(10 * time.Millisecond)
	}
	if !sess.Lost() {
		t.Fatal("a closed transport must latch lost")
	}
}
