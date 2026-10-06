// Failure reporting: one funnel for every error the command line can produce.
//
// Errors come in two shapes — a usage error (unknown command, unknown flag,
// wrong argument count) additionally gets that command's usage block, and a
// coded error carries its own exit code for a run that could not happen. Every
// other failure is a mistake the tool explains to a human and leaves the shell's
// exit status at 0, so a typo never looks like a failed run.

package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// exitError is an error with an exit code; Main prints the message.
type exitError struct {
	code ExitCode
	err  error
}

func (e exitError) Error() string { return e.err.Error() }

// usageError is a usage-level error (unknown command, unknown flag, wrong
// argument count): the message plus that command's usage block.
type usageError struct {
	err error
	cmd *cobra.Command
}

func (e usageError) Error() string { return e.err.Error() }

// failf builds an error with an exit code; Main prints the message.
func failf(code ExitCode, format string, args ...any) error {
	return exitError{code: code, err: fmt.Errorf(format, args...)}
}

// silentError ends the process at its code with nothing printed: a mode whose
// stdout and stderr already are the answer — the probe reader hands back a
// tier's own streams and status — has nothing to add to them, and a line karma
// wrote there would be read as the tier's own.
type silentError struct{ code ExitCode }

func (e silentError) Error() string { return "" }

// usagef builds a usage error; Main appends the usage block.
func usagef(cmd *cobra.Command, format string, args ...any) error {
	return usageError{err: fmt.Errorf(format, args...), cmd: cmd}
}

// reportError prints one failure and returns the exit code: a usage error gets
// the command's usage block appended, a coded error returns its own code, and
// anything else — a mistake the message has already explained — returns 0.
func reportError(w io.Writer, err error) int {
	return reportErrorWith(w, err, stylesFor(w))
}

// reportErrorWith renders at a fixed set of styles; tests use it to force color
// on a capture buffer.
func reportErrorWith(w io.Writer, err error, st streamStyles) int {
	// A silent ending owns both streams already: its status is the whole report.
	var silent silentError
	if errors.As(err, &silent) {
		return int(silent.code)
	}
	msg := "karma: " + err.Error()
	// A suggestion tail ("Did you mean: …") is guidance, not the failure, so it
	// takes the hint color while the failure itself stays red.
	if i := strings.Index(msg, "Did you mean:"); i > 0 {
		fmt.Fprintf(w, "%s%s\n", st.err(msg[:i]), st.hint(msg[i:]))
	} else {
		fmt.Fprintln(w, st.err(msg))
	}
	var usage usageError
	if errors.As(err, &usage) {
		styledUsageWith(w, usage.cmd, st)
	}
	var coded exitError
	if errors.As(err, &coded) {
		return int(coded.code)
	}
	return int(ExitOK)
}

// flagErrorText turns pflag's flag errors into short sentences; an unfamiliar
// shape keeps its original text.
func flagErrorText(err error) string {
	var (
		notExist *pflag.NotExistError
		required *pflag.ValueRequiredError
		invalid  *pflag.InvalidValueError
		syntax   *pflag.InvalidSyntaxError
	)
	switch {
	case errors.As(err, &notExist):
		if shorts := notExist.GetSpecifiedShortnames(); shorts != "" {
			return "unknown shorthand flag -" + notExist.GetSpecifiedName()
		}
		return "unknown flag --" + notExist.GetSpecifiedName()
	case errors.As(err, &required):
		if shorts := required.GetSpecifiedShortnames(); shorts != "" {
			return "flag -" + required.GetSpecifiedName() + " needs a value"
		}
		return "flag --" + required.GetSpecifiedName() + " needs a value"
	case errors.As(err, &invalid):
		return "invalid value " + invalid.GetValue() + " for flag --" + invalid.GetFlag().Name
	case errors.As(err, &syntax):
		return "bad flag syntax: " + syntax.GetSpecifiedFlag()
	}
	return err.Error()
}
