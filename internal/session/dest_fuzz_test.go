package session

import (
	"strings"
	"testing"
)

func FuzzParseSSHDestination(f *testing.F) {
	f.Add("root@10.0.0.8")
	f.Add("ssh://user@host:2222")
	f.Add("ssh://user@[::1]:22")
	f.Add("[::1]")
	f.Add("a@b:c")
	f.Add("@")
	f.Add("")
	f.Add("ssh://u@h:")
	f.Fuzz(func(t *testing.T, target string) {
		dest, err := ParseSSHDestination(target)
		if err != nil {
			return
		}
		if dest.Host == "" {
			t.Fatalf("parsed %q to an empty host", target)
		}
		if dest.Port < 1 || dest.Port > MaxPort {
			t.Fatalf("parsed %q to an out-of-range port %d", target, dest.Port)
		}
		if !strings.Contains(dest.Display(), dest.Host) {
			t.Fatalf("Display %q lost host %q", dest.Display(), dest.Host)
		}
	})
}
