// Built-in readers under the local command: cat and ls print what karma's own
// in-process implementations produce and never run the host's binaries, so an
// LD_PRELOAD hook on cat or ls cannot reshape the output. ls paints its rows
// with the report's own ls-l coloring, so the standalone output reads like
// the panels; a pipe or capture drops the color automatically. Failures are
// phrased the way the host's tools phrase them, a failed operand never hides
// the rest, and a failed read exits 1.

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"

	// The two built-in readers are the local channel's own in-process view of the
	// filesystem, so they call internal/localfs directly: no check, no catalog.
	"karma/internal/localfs"
	"karma/internal/model"
	"karma/internal/render"
)

func newCatCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cat FILE...",
		Short: "Print files, read in process",
		Long: "Print each file's bytes on stdout in order, read by karma itself rather than the host's " +
			"cat — a preload hook on the host binary cannot reshape the output. A file that cannot be " +
			"read is reported after the rest have printed; the command then exits 1.",
		Args: atLeastOneArg("cat needs at least one file: karma local cat FILE..."),
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			var first error
			for _, path := range args {
				data, err := localfs.Cat(path)
				if err != nil {
					err = catError(path, err)
					if first == nil {
						first = err
					}
					continue
				}
				if _, err = w.Write(data); err != nil {
					return err
				}
			}
			return readerFailure(first)
		},
	}
}

func newLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls [PATH...]",
		Short: "List directories, read in process",
		Long: "Print each directory's entries in the collection's ls -l row shape (full paths, newest first, " +
			"hidden entries included) with the report's ls-l coloring, read by karma itself rather than the " +
			"host's ls — a preload hook on the host binary cannot hide an entry. With no path the current " +
			"directory is listed, the way ls itself defaults; several paths get an \"== path\" section header " +
			"each, and a path that cannot be read is reported after the rest have printed; the command " +
			"then exits 1. A file operand prints its own row.",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if len(paths) == 0 {
				paths = []string{"."}
			}
			text, err := localfs.Ls(paths)
			w := cmd.OutOrStdout()
			if text != "" {
				st := stylesFor(w)
				for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
					// section headers read like the panels' source titles
					if strings.HasPrefix(line, "== ") {
						line = st.bold(line)
					} else {
						line = render.SyntaxLine(model.SyntaxLsL, line)
					}
					fmt.Fprintln(w, line)
				}
			}
			if err != nil {
				var pathErr *fs.PathError
				if errors.As(err, &pathErr) {
					return readerFailure(readError("ls", pathErr.Path, err))
				}
				return readerFailure(readError("ls", paths[0], err))
			}
			return nil
		},
	}
}

// readerFailure is one built-in reader's failure: the message stays the host
// tool's own sentence, and the command exits 1 — the status a failed read
// carries — so a script that reads $? sees the failure instead of success. The
// operands that did read have already printed either way.
func readerFailure(err error) error {
	if err == nil {
		return nil
	}
	return failf(1, "%s", err.Error())
}

// atLeastOneArg is cat's argument check: one or more positional words, with
// the command's own spelling in the usage error.
func atLeastOneArg(spelling string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return usagef(cmd, "%s", spelling)
		}
		return nil
	}
}

// catError phrases one cat failure: a directory operand keeps coreutils'
// own sentence, the rest read like the host tool's errno lines.
func catError(path string, err error) error {
	if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
		return fmt.Errorf("cat %s: is a directory", path)
	}
	return readError("cat", path, err)
}

// readError phrases a reader failure the way the host's own tools do — the
// operation, the path, the errno sentence — so the report reads the same
// whether karma or the tool it replaces said it.
func readError(op, path string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s %s: no such file or directory", op, path)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s %s: permission denied", op, path)
	default:
		return fmt.Errorf("%s %s: %w", op, path, err)
	}
}
