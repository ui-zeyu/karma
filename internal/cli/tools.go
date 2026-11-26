// The local readers: cat and ls read in process, so a preload hook on the
// host's own tools cannot reshape the answer.

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"karma/internal/localfs"
	chrome "karma/internal/panel"
)

func newCatCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "cat FILE...",
		Short:   "Print files, read in process",
		Args:    atLeastOneArg("cat needs at least one file: karma cat FILE..."),
		Example: "karma cat /etc/passwd",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			color := isTerminal(w)
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
				if _, err = w.Write(highlightContent(path, data, color)); err != nil {
					return err
				}
			}
			return readerFailure(first)
		},
	}
}

func newLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls [PATH...]",
		Short:   "List directories, read in process",
		Example: "karma ls /etc /var/log",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if len(paths) == 0 {
				paths = []string{"."}
			}
			text, err := localfs.Ls(paths)
			w := cmd.OutOrStdout()
			color := isTerminal(w)
			if text != "" {
				for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
					if strings.HasPrefix(line, "== ") {
						// A section header reads like the panels' source titles.
						fmt.Fprintln(w, chrome.Paint(color, "\x1b[1m", line))
						continue
					}
					fmt.Fprintln(w, lsRow(color, line))
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

func readerFailure(err error) error {
	if err == nil {
		return nil
	}
	return failf(ExitRead, "%s", err.Error())
}

func catError(path string, err error) error {
	if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
		return fmt.Errorf("cat %s: is a directory", path)
	}
	return readError("cat", path, err)
}

func readError(op, path string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s %s: no such file or directory", op, path)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s %s: permission denied", op, path)
	case errors.Is(err, localfs.ErrNotRegular):
		return fmt.Errorf("%s %s: not a regular file", op, path)
	default:
		return fmt.Errorf("%s %s: %w", op, path, err)
	}
}
