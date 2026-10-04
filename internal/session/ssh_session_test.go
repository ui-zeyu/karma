package session

import (
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestCommandExitCode(t *testing.T) {
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
