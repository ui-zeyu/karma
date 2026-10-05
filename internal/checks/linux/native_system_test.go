// tests for the in-process system reads: the logind session count procps uses
// for the uptime banner's user figure.

package linux

import "testing"

func TestSessionIsUser(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"user session", "UID=0\nUSER=root\nACTIVE=1\nCLASS=user\n", true},
		{"user-early", "UID=0\nCLASS=user-early\n", true},
		{"manager", "UID=0\nCLASS=manager-early\n", false},
		{"greeter", "UID=1000\nCLASS=greeter\n", false},
		{"no class", "UID=0\nUSER=root\n", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		if got := sessionIsUser([]byte(c.data)); got != c.want {
			t.Errorf("%s: sessionIsUser = %v, want %v", c.name, got, c.want)
		}
	}
}
