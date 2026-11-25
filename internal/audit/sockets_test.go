package audit

import "testing"

func TestParseSocketLineAcceptsTheProcFallback(t *testing.T) {
	socket, ok := parseSocketLine("tcp LISTEN 127.0.0.11:46193 *:* uid=129125")
	if !ok || socket.Proto != "tcp" || socket.Local != "127.0.0.11:46193" || socket.Peer != "*:*" {
		t.Fatalf("socket = %+v ok=%v", socket, ok)
	}
}
