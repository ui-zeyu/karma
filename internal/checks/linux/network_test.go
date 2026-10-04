package linux

import (
	"strings"
	"testing"
)

// decodeEndpoint restores the /proc/net hex form: v4 is one little-endian word,
// v6 is four with each word reversed in place.
func TestDecodeEndpoint(t *testing.T) {
	cases := []struct {
		field string
		want  string
	}{
		{"0100007F:0016", "127.0.0.1:22"},                             // 127.0.0.1:22
		{"00000000:0000", "0.0.0.0:0"},                                // wildcard
		{"AF01A8C0:04D2", "192.168.1.175:1234"},                       // little-endian word
		{"00000000000000000000000001000000:0016", "[::1]:22"},         // ::1
		{"0000000000000000FFFF00000100007F:1F90", "[127.0.0.1]:8080"}, // v4-mapped renders as plain v4
	}
	for _, c := range cases {
		got, err := decodeEndpoint(c.field)
		if err != nil {
			t.Errorf("decodeEndpoint(%s): %v", c.field, err)
			continue
		}
		if got != c.want {
			t.Errorf("decodeEndpoint(%s) = %s, want %s", c.field, got, c.want)
		}
	}
	if _, err := decodeEndpoint("127.0.0.1"); err == nil {
		t.Error("a field without a port should fail")
	}
	if _, err := decodeEndpoint("0100:zz"); err == nil {
		t.Error("a bad port should fail")
	}
}

// parseProcNet turns one /proc/net body into `state  local  remote` lines; the
// section title tells TCP from UDP state semantics.
func TestParseProcNet(t *testing.T) {
	tcp := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue",
		"   0: 0100007F:0016 00000000:0000 0A 00000000:00000000",
		"   1: 0100007F:8193 0100007F:1F90 01 00000000:00000000",
	}, "\n")
	shaped := parseProcNet("/proc/net/tcp", tcp)
	lines := strings.Split(shaped.Text, "\n")
	if lines[0] != "LISTEN  127.0.0.1:22  0.0.0.0:0" {
		t.Fatalf("listen row: %q", lines[0])
	}
	if lines[1] != "ESTAB  127.0.0.1:33171  127.0.0.1:8080" {
		t.Fatalf("established row: %q", lines[1])
	}

	// A connectionless socket is TCP_CLOSE(07) in the kernel; in a UDP section it
	// reads UNCONN instead of the TCP table's CLOSE.
	udp := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue",
		"   8: 00000000:0035 00000000:0000 07 00000000:00000000",
	}, "\n")
	shaped = parseProcNet("/proc/net/udp", udp)
	if !strings.Contains(shaped.Text, "UNCONN  0.0.0.0:53") {
		t.Fatalf("udp row should read UNCONN: %q", shaped.Text)
	}

	// The header row (sl …) is not table data.
	shaped = parseProcNet("/proc/net/tcp", "  sl  local_address rem_address   st\n")
	if shaped.Text != "" {
		t.Fatalf("the header row should be dropped: %q", shaped.Text)
	}
}
