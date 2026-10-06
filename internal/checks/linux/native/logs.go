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

// AccessLog mirrors AccessLogScript: one summary per existing log file, built
// from the file's own tail. Nothing here runs the host's awk — the summary is
// counted in process, so a preload hook on the target's awk cannot reshape what
// its own logs say.
func AccessLog(paths []string, keep *regexp.Regexp) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		for _, path := range localfs.ExpandFiles(paths) {
			body, err := localfs.Tail(path, script.AccessLogWindow)
			if err != nil {
				continue
			}
			b.WriteString(script.AccessLogBody(path, strings.Split(string(body), "\n"), keep))
		}
		return b.String(), nil
	}
}
