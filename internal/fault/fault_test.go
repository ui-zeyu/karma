package fault

import (
	"errors"
	"strings"
	"testing"
)

// A boundary that returns normally is unchanged: tests and callers rely on the
// error it produced surviving Catch as it is.
func TestCatchReturnsTheCallersError(t *testing.T) {
	want := errors.New("the read failed")
	err := Catch("reader", func() error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("Catch should hand back the caller's own error, got %v", err)
	}
	if err := Catch("reader", func() error { return nil }); err != nil {
		t.Fatalf("a boundary that ends well reports nothing, got %v", err)
	}
}

// The whole point: a panic becomes a value, and the process keeps running.
func TestCatchTurnsAPanicIntoAValue(t *testing.T) {
	var after bool
	err := Catch("harvest stdout reader", func() error {
		panic("index out of range")
	})
	after = true
	if !after {
		t.Fatal("the panic should not have left Catch")
	}
	var recovered *Panic
	if !errors.As(err, &recovered) {
		t.Fatalf("a panic should come back as a *Panic, got %T (%v)", err, err)
	}
	for _, want := range []string{"harvest stdout reader", "index out of range"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the message should name %q, got %q", want, err.Error())
		}
	}
	if !strings.Contains(string(recovered.Stack), "TestCatchTurnsAPanicIntoAValue") {
		t.Fatal("the panic should carry the stack of the boundary that broke")
	}
}

// panicValue is a value the caller might panic with that carries no message of
// its own.
type panicValue struct{ Code int }

// A panic value of any type is reportable: the message is what the report has.
func TestPanicValueOfAnyType(t *testing.T) {
	err := Catch("render", func() error { panic(panicValue{Code: 7}) })
	if !strings.Contains(err.Error(), "{7}") {
		t.Fatalf("the panic value should reach the message, got %q", err.Error())
	}
}
