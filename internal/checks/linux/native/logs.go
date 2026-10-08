// native tiers of the log checks: the web access-log summary the local channel
// builds in process from the tail of each log file.

package native

import (
	"context"
	"regexp"
	"strings"

	"karma/internal/localfs"
	"karma/internal/script"
)

// AccessLogFile builds one log file's summary from the file's own tail. Nothing
// here runs the host's awk — the summary is counted in process, so a preload hook
// on the target's awk cannot reshape what its own logs say.
func AccessLogFile(path string, keep *regexp.Regexp) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		body, err := localfs.Tail(path, script.AccessLogWindow)
		if err != nil {
			return "", nil
		}
		return script.AccessLogBody(strings.Split(string(body), "\n"), keep), nil
	}
}
