// process: process tree, deleted binaries, processes whose cwd is in a temp directory.
package linux

import (
	"karma/internal/define"
	"karma/internal/model"
)

const cwdTmpScript = `
for c in /proc/[0-9]*/cwd; do
  t=$(readlink "$c" 2>/dev/null) || continue
  case "$t" in /tmp/*|/var/tmp/*|/dev/shm/*) printf '%s -> %s\n' "${c%/cwd}" "$t";; esac
done
`

const deletedExeScript = `
for e in /proc/[0-9]*/exe; do
  t=$(readlink "$e" 2>/dev/null) || continue
  case "$t" in *\(deleted\)) printf '%s -> %s\n' "${e#/proc/}" "$t";; esac
done
`

// hiddenProcsScript lists pids from /proc and from ps, and the set difference is
// the processes "present in proc but not reported by ps". Plain POSIX composition
// (the target's /bin/sh is dash, no <()); a final /proc recheck verifies: a process
// that happened to exit between the two listings (including karma's own concurrent
// probes) is gone by then, while a process hidden from ps remains in /proc, so only
// the latter stays in the difference.
const hiddenProcsScript = `{ ls /proc | grep -E '^[0-9]+$'; ps -eo pid= | tr -d ' '; } | sort -n | uniq -u` +
	` | while read -r p; do [ -d "/proc/$p" ] && echo "$p"; done`

// ProcessChecks covers processes.
var ProcessChecks = []*model.Check{
	define.LinuxCheck("ps", "Process tree", model.AspectProcess,
		[]model.Probe{
			{Label: "ps", Inv: model.NewCommand("ps", "auxwwf")},
			{Label: "pstree", Inv: model.NewCommand("pstree", "-ap")},
			{Label: "ps-ef", Inv: model.NewCommand("ps", "-ef")},
		},
		define.CheckOpt{
			Syntax: "table",
			Rules: []model.Rule{
				model.NewRule("ps-tmp-path", `\s/(?:tmp|var/tmp|dev/shm)/\S*`, model.Medium,
					"command line references a temp-directory path (drop-and-exec investigation)"),
				// A web service account spawning a shell/interpreter is webshell execution in
				// progress; normal web process names (php-fpm, httpd, gunicorn) do not contain
				// these words
				model.NewRule("ps-service-shell",
					`^(?:www-data|wwwrun|apache|nginx|nobody)\s`+
						`.*\b(?:(?:ba|z|da|k)?sh|python[0-9.]*|perl|ruby|nc|socat)\b`,
					model.Medium, "service account running a shell/interpreter (typical webshell execution)"),
				define.KeywordRule,
			},
		}),
	define.LinuxCheck("top", "Resource usage snapshot", model.AspectProcess,
		[]model.Probe{
			// head is the shape this probe wants: stop when enough is read, count it as a
			// complete answer, and do not mark it "truncated"
			{Label: "top", Inv: model.NewCommand("top", "-b", "-n", "1"), Head: 25},
			{Label: "ps-cpu", Inv: model.NewCommand("ps", "aux", "--sort=-%cpu"), Head: 10},
			{Label: "ps-mem", Inv: model.NewCommand("ps", "aux", "--sort=-%mem"), Head: 10},
		},
		define.CheckOpt{Syntax: "table", Rules: []model.Rule{define.KeywordRule}}),
	define.LinuxCheck("deleted-exe", "Deleted binaries still running", model.AspectProcess,
		[]model.Probe{{Label: "proc-exe", Inv: model.Shell{Script: deletedExeScript}}},
		define.CheckOpt{}),
	define.LinuxCheck("cwd-tmp", "Processes with cwd in a temp directory", model.AspectProcess,
		[]model.Probe{{Label: "proc-cwd", Inv: model.Shell{Script: cwdTmpScript}}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("proc-cwd-tmp", `^/proc/\d+ -> /(?:tmp|var/tmp|dev/shm)/`, model.High,
					"process cwd is in a temp directory"),
			},
		}),
	define.LinuxCheck("hidden-procs", "proc vs ps process comparison", model.AspectProcess,
		[]model.Probe{{Label: "ps", Inv: model.Shell{Script: hiddenProcsScript}, Requires: []string{"ps"}}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("proc-not-in-ps", `^[0-9]+$`, model.High,
					"present in /proc but not seen by ps (process-hiding sign; occasional false positive from a just-exited process)"),
			},
		}),
}
