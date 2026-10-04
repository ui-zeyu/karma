// process: process tree, deleted files still in use, processes whose cwd is in a temp directory.

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

// deletedLinksScript walks every /proc link the kernel resolves for a process:
// exe, cwd, and all open file descriptors. When the backing file is unlinked
// the kernel appends " (deleted)" to the link target — the same mark lsof
// reports — so held-open deleted files and directories stay visible on hosts
// without lsof.
const deletedLinksScript = `
for l in /proc/[0-9]*/exe /proc/[0-9]*/cwd /proc/[0-9]*/fd/*; do
  t=$(readlink "$l" 2>/dev/null) || continue
  case "$t" in *\(deleted\)) printf '%s -> %s\n' "${l#/proc/}" "$t";; esac
done
`

// lsofScript is the raw +L1 listing: every open file whose link count dropped
// to zero, plus lsof's stat-failure false positives on plain memory-mapped
// libraries (reported as 0). Filtering happens in the reader via the check's
// keep filter, so the chain sees lsof's own exit code; the kernel's
// "(deleted)" name suffix is the mark the filter keeps. -n skips name lookups
// that could stall the probe.
const lsofScript = `lsof -wn +L1 2>/dev/null`

// findDeletedScript runs one find process over the same /proc link tree the
// shell walk below covers, doing every lstat in-process instead of one readlink
// fork per link. -lname matches the kernel's "(deleted)" link-target suffix.
// -lname/-printf are GNU extensions: a find without them fails the probe and
// the chain falls through to the walk.
const findDeletedScript = `find /proc/[0-9]*/fd /proc/[0-9]*/exe /proc/[0-9]*/cwd` +
	` -maxdepth 1 -lname '*(deleted)' -printf '%p -> %l\n' 2>/dev/null`

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
		define.CheckOpt{Syntax: "top", Rules: []model.Rule{define.KeywordRule}}),
	define.LinuxCheck("deleted-exe", "Deleted files still in use", model.AspectProcess,
		[]model.Probe{
			// Three tiers: lsof is the richest (command, user, fd mode per open
			// file, plus mapped libraries); find covers the fd/cwd/exe links in
			// one process; the shell walk is the portable last resort for hosts
			// whose find has neither -lname nor -printf. lsof runs raw and is
			// capped by the reader's scan budget: a source-side line cap would
			// cut the stream before the keep filter sees the deleted rows.
			{Label: "lsof", Inv: model.Shell{Script: lsofScript}, Requires: []string{"lsof"}},
			{Label: "find", Inv: model.Shell{Script: findDeletedScript}, LineLimit: 200},
			{Label: "proc-links", Inv: model.Shell{Script: deletedLinksScript}, LineLimit: 200},
		},
		define.CheckOpt{
			// Keep only rows the kernel marked deleted; signal rows bypass keep
			// filters and are always kept.
			Filters: []model.LineFilter{
				model.NewFilter("deleted-lines", `\(deleted\)`, model.FilterKeep),
			},
		}),
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
