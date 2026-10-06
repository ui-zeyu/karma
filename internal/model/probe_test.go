package model

import (
	"context"
	"testing"
)

// A tier's invocation is either something the target runs or a body karma runs
// itself; the two sides of the wire are a separate question, and the local
// channel is the one where karma stands on the collected host.
func TestInvocationKindsAndTheTwoSidesOfTheWire(t *testing.T) {
	native := Probe{Label: "lsmod", Inv: Native{Body: func(context.Context) (string, error) { return "", nil }}}
	if _, ok := native.Inv.(Native); !ok {
		t.Fatal("a tier whose work karma does itself carries a Native body")
	}
	command := Probe{Label: "ss", Inv: NewCommand("ss", "-tunap")}
	if _, ok := command.Inv.(Command); !ok {
		t.Fatal("a tier that calls a host tool carries that command")
	}
	if !ChanSSH.Remote() || !ChanTTYD.Remote() {
		t.Fatal("a channel that reaches the target from outside is remote")
	}
	if ChanLocal.Remote() {
		t.Fatal("the local channel runs where karma stands")
	}
}
