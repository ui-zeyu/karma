// process: process tree, the session capability set (container escape
// surface), and a cryptominer hunt.

package linux

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

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

// sessionCapsScript collects the session's own capability set. Inside a
// container that set is the standing escape surface, so it prints in full;
// on the host it is fixed by the login uid (root shows the full set by
// definition), so the context line is the whole answer. Container detection
// reads the host's own markers: /.dockerenv (Docker), /run/.containerenv
// (Podman), the PID 1 cgroup path (docker/containerd/kubepods/libpod/lxc/kata
// scopes), and systemd-detect-virt. capsh (libcap2-bin, near-universal)
// decodes the names; the fallback tier reads the /proc/self/status masks and
// decodeCapMasks decodes them locally.
const sessionCapsScript = `
if [ -f /.dockerenv ] || [ -f /run/.containerenv ]` +
	` || grep -qaE "(docker|containerd|kubepods|libpod|lxc|kata)[/.-]" /proc/1/cgroup 2>/dev/null` +
	` || systemd-detect-virt --container >/dev/null 2>&1; then
  echo "context: container"
else
  echo "context: host"
  exit 0
fi
if command -v capsh >/dev/null 2>&1; then
  echo "== capsh --print"
  capsh --print 2>/dev/null
else
  echo "== /proc/self/status"
  grep "^Cap" /proc/self/status 2>/dev/null
fi
`

// capNames is the Linux capability list by bit number (uapi/linux/capability.h).
// A newer kernel's bits past the table decode to their number instead of
// garbage, and a missing capsh never blocks the check.
var capNames = []string{
	"cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner",
	"cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap",
	"cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast",
	"cap_net_admin", "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner",
	"cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace",
	"cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
	"cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod",
	"cap_lease", "cap_audit_write", "cap_audit_control", "cap_setfcap",
	"cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm",
	"cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf",
	"cap_checkpoint_restore",
}

// capMaskLine matches one /proc/self/status capability line: a Cap* key and a
// hex mask (kallsyms-style leading zeros included).
var capMaskLine = regexp.MustCompile(`^(Cap\w+:[ \t]+)([0-9a-fA-F]{8,16})[ \t]*$`)

// decodeCapMasks is the Adapt of the status tier: it appends the decoded
// capability names to each non-zero mask line, so both tiers read as names and
// the same rules light on either. A body with no set mask is returned as is.
func decodeCapMasks(_ string, body string) *model.Shaped {
	lines := strings.Split(body, "\n")
	changed := false
	for i, line := range lines {
		m := capMaskLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		value, err := strconv.ParseUint(m[2], 16, 64)
		if err != nil {
			continue
		}
		names := capBitNames(value)
		if len(names) == 0 {
			continue
		}
		lines[i] = fmt.Sprintf("%s%s  = %s", m[1], m[2], strings.Join(names, ", "))
		changed = true
	}
	if !changed {
		return nil
	}
	return &model.Shaped{Text: strings.Join(lines, "\n")}
}

// capBitNames decodes one mask into capability names, lowest bit first.
func capBitNames(mask uint64) []string {
	var names []string
	for bit := 0; mask>>bit != 0; bit++ {
		if mask>>bit&1 == 0 {
			continue
		}
		if bit < len(capNames) {
			names = append(names, capNames[bit])
		} else {
			names = append(names, fmt.Sprintf("bit%d", bit))
		}
	}
	return names
}

// minerFamily: cryptominer family names, from the LinuxCheck list plus the
// 2020+ kdevtmpfsi/kinsing wave and the kthreadd impostors. A plain
// alternation so the same string serves the shell probe's ERE and the rule's
// RE2. Keep in sync with minerScript below.
const minerFamily = `xmrig|xmr-stak|minerd|cpuminer|kworkerds|kdevtmpfsi|kinsing|` +
	`watchbog|sustes|ddgs|kthreaddi|kthreaddk|sysupdate|sysguard|networkservice|cryptonight`

// minerScript hunts cryptominers in place: process lines matched out of a ps
// snapshot (grep -v drops this pipeline's own lines, which carry the pattern),
// attributes of the classic fixed drop paths, and a bounded name walk of the
// temp directories. Every arm is quiet when nothing matches; the deep
// time-clustered hunt stays with the mtime subcommand.
//
// Checks run concurrently, so on a clean host the ps check's snapshot still
// holds this script's own sh line, and the global known-malware-name /
// hidden-tmp-path rules light on it. Accepted: spelling the names plainly is
// worth one recognizable karma-owned line, and the split-quote trick to dodge
// it was reverted as unreadable. \b bounds every name so substrings stay out
// (macOS runs a legit daemon named networkserviceproxy).
const minerScript = `
pat='\bxmrig\b|\bxmr-stak\b|\bminerd\b|\bcpuminer\b|\bkworkerds\b|\bkdevtmpfsi\b|\bkinsing\b|\bwatchbog\b|\bsustes\b|\bddgs\b|\bkthreaddi\b|\bkthreaddk\b|\bsysupdate\b|\bsysguard\b|\bnetworkservice\b|\bcryptonight\b|\bstratum\+?(tcp|ssl):'
echo "== ps"
ps auxww | grep -aE "$pat" | grep -av grep
echo "== drop paths"
LC_ALL=C ls -l /tmp/.a /var/tmp/.a /dev/.a /dev/shm/.a /tmp/xmr /tmp/config.json /var/tmp/config.json /dev/shm/config.json /tmp/secure.sh /tmp/auth.sh /usr/.work/work64 2>/dev/null
echo "== temp names"
find /tmp /var/tmp /dev/shm -xdev -maxdepth 4 -type f \( -iname '*xmrig*' -o -iname '*minerd*' -o -iname '*cpuminer*' -o -iname 'kworkerds*' -o -iname 'kdevtmpfsi*' -o -iname 'kinsing*' -o -iname 'watchbog*' -o -iname 'sustes*' -o -iname 'sysupdate*' -o -iname 'sysguard*' -o -iname 'networkservice*' -o -iname 'config.json' \) -exec ls -l {} + 2>/dev/null
`

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
					"command line references temp path"),
				// A web service account spawning a shell/interpreter is webshell execution in
				// progress; normal web process names (php-fpm, httpd, gunicorn) do not contain
				// these words
				model.NewRule("ps-service-shell",
					`^(?:www-data|wwwrun|apache|nginx|nobody)\s`+
						`.*\b(?:(?:ba|z|da|k)?sh|python[0-9.]*|perl|ruby|nc|socat)\b`,
					model.Medium, "service account running a shell/interpreter (typical webshell execution)"),
				// A JDWP agent on a Java command line means the debug port executes code as
				// the process for anyone who can reach it — a finding even when the process
				// is the application itself
				model.NewRule("ps-jdwp", `\bagentlib:jdwp\b|\brunjdwp\b`, model.High,
					"JDWP debug agent on the command line (code execution via the debug port)"),
				// python -m http.server hands its whole working directory to the network;
				// during an incident it is more often the staging/exfil channel than a
				// sharing convenience
				model.NewRule("ps-http-server", `-m\s+(?:http\.server|SimpleHTTPServer)\b`, model.Medium,
					"Python one-line HTTP server exposing its directory"),
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
	define.LinuxCheck("proc-caps", "Session capability set (container escape surface)", model.AspectProcess,
		[]model.Probe{{Label: "caps", Inv: model.Shell{Script: sessionCapsScript}, Adapt: decodeCapMasks}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("cap-container-context", `^context: container`, model.Medium,
					"session runs inside a container (the set below is the escape surface)"),
				// The dangerous caps fire only here: the capability table prints only in the
				// container branch, and on the host the same names are the root default
				model.NewRule("cap-sys-admin", `\bcap_sys_admin\b`, model.Critical,
					"cap_sys_admin in the session set (mount/cgroup writes: container escape)"),
				model.NewRule("cap-dac-read-search", `\bcap_dac_read_search\b`, model.High,
					"cap_dac_read_search (DAC bypass; outside the default container set)"),
				model.NewRule("cap-sys-module", `\bcap_sys_module\b`, model.High,
					"cap_sys_module (kernel module load; outside the default container set)"),
				model.NewRule("cap-sys-ptrace", `\bcap_sys_ptrace\b`, model.High,
					"cap_sys_ptrace (outside the default container set)"),
			},
		}),
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
					"in /proc but not in ps (or just exited)"),
			},
		}),
	define.LinuxCheck("miner", "Cryptominer hunt (processes and drop paths)", model.AspectProcess,
		[]model.Probe{{Label: "scan", Inv: model.Shell{Script: minerScript}, LineLimit: 200}},
		define.CheckOpt{
			Syntax: "table",
			// The drop-path and temp-name sections are ls -l shape, the ps section a
			// process table; one override per section keeps both colored
			SectionSyntax: []model.SectionSyntax{
				{Title: "drop paths", Syntax: "ls-l"},
				{Title: "temp names", Syntax: "ls-l"},
			},
			Rules: []model.Rule{
				// Fires on process lines and on file lines alike: a file literally named
				// after a miner family is the same finding
				model.NewRule("miner-family", `\b(?:`+minerFamily+`)\b`, model.Critical,
					"known cryptominer family name"),
				model.NewRule("miner-stratum", `stratum\+?(?:tcp|ssl):`, model.Critical,
					"Stratum mining-pool protocol in a command line"),
				model.NewRule("miner-config", `/(?:tmp|var/tmp|dev/shm)/config\.json(?:\s|$)`, model.High,
					"miner config at a known drop path"),
			},
		}),
}
