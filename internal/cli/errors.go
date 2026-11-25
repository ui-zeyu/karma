// Failure reporting: one funnel for every error the command line can produce.

package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type exitError struct {
	code ExitCode
	err  error
}

func (e exitError) Error() string { return e.err.Error() }

type usageError struct {
	err error
	cmd *cobra.Command
}

func (e usageError) Error() string { return e.err.Error() }

func failf(code ExitCode, format string, args ...any) error {
	return exitError{code: code, err: fmt.Errorf(format, args...)}
}

func usagef(cmd *cobra.Command, format string, args ...any) error {
	return usageError{err: fmt.Errorf(format, args...), cmd: cmd}
}

func reportError(w io.Writer, err error) int {
	fmt.Fprintln(w, "karma: "+err.Error())
	var usage usageError
	if errors.As(err, &usage) && usage.cmd != nil {
		fmt.Fprintln(w, strings.TrimRight(usage.cmd.UsageString(), "\n"))
	}
	var coded exitError
	if errors.As(err, &coded) {
		return int(coded.code)
	}
	return int(ExitOK)
}

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
