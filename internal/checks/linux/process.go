// process: process tree, the session capability set (container escape
// surface), and a cryptominer hunt.

package linux

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/samber/lo"

	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/model"
)

// tmpGlobs is tmpDirs as the shell case pattern the cwd walk matches: every temp
// directory and everything below it.
var tmpGlobs = strings.Join(lo.Map(tmpDirs, func(dir string, _ int) string { return dir + "/*" }), "|")

// cwdTmpScript prints every process whose working directory sits inside a temp
// directory.
var cwdTmpScript = `
for c in /proc/[0-9]*/cwd; do
  t=$(readlink "$c" 2>/dev/null) || continue
  case "$t" in ` + tmpGlobs + `) printf '%s -> %s\n' "${c%/cwd}" "$t";; esac
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
// the latter stays in the difference. The leading command -v gate is correctness,
// not economy: the pipeline would swallow a missing ps and report every /proc pid
// as hidden.
const hiddenProcsScript = `command -v ps >/dev/null 2>&1 || exit 127
` + `{ ls /proc | grep -E '^[0-9]+$'; ps -eo pid= | tr -d ' '; } | sort -n | uniq -u` +
	` | while read -r p; do [ -d "/proc/$p" ] && echo "$p"; done`

// containerMarkers is the ERE that recognizes a container's cgroup scope, whose
// runtimes each spell their own scope name. One string feeds both readings: the
// script's grep over /proc/1/cgroup and the local RE2 compiled from it, so the
// two cannot drift apart.
const containerMarkers = `(docker|containerd|kubepods|libpod|lxc|kata)[/.-]`

// containerCgroupRe is containerMarkers as the local read's pattern.
var containerCgroupRe = regexp.MustCompile(`(?i)` + containerMarkers)

// sessionCapsScript collects the session's own capability set. Inside a
// container that set is the standing escape surface, so it prints in full;
// on the host it is fixed by the login uid (root shows the full set by
// definition), so the context line is the whole answer. Container detection
// reads the host's own markers: /.dockerenv (Docker), /run/.containerenv
// (Podman), the PID 1 cgroup path (the runtimes containerMarkers names), and
// systemd-detect-virt. capsh (libcap2-bin, near-universal) decodes the names;
// the fallback tier reads the /proc/self/status masks and native.DecodeCapMasks
// decodes them locally.
const sessionCapsScript = `
if [ -f /.dockerenv ] || [ -f /run/.containerenv ]` +
	` || grep -qaE "` + containerMarkers + `" /proc/1/cgroup 2>/dev/null` +
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

// minerFamilies: cryptominer family names, from the LinuxCheck list plus the
// 2020+ kdevtmpfsi/kinsing wave and the kthreadd impostors. One list feeds both
// readings — the process-line alternation the shell probe's grep -E and the local
// RE2 scan share, and the rule's alternation — so they cannot drift apart.
var minerFamilies = []string{
	"xmrig", "xmr-stak", "minerd", "cpuminer", "kworkerds", "kdevtmpfsi", "kinsing",
	"watchbog", "sustes", "ddgs", "kthreaddi", "kthreaddk", "sysupdate", "sysguard",
	"networkservice", "cryptonight",
}

// minerFamily is minerFamilies as the rule's plain alternation.
var minerFamily = strings.Join(minerFamilies, "|")

// minerPsSource is minerFamilies as the process-line alternation, spelled so that
// both readings work: the target's grep -E and the local RE2 compile it the same
// way (plain capture groups -- GNU grep parses (?: literally). \b bounds every
// name so substrings stay out (macOS runs a legit daemon named
// networkserviceproxy); the Stratum pool protocol is the one non-name branch.
var minerPsSource = `\b` + strings.Join(minerFamilies, `\b|\b`) + `\b|\bstratum\+?(tcp|ssl):`

var minerPsPattern = regexp.MustCompile(minerPsSource)

// minerDropPaths is the fixed drop-path list the ls section reads.
var minerDropPaths = []string{
	"/tmp/.a", "/var/tmp/.a", "/dev/.a", "/dev/shm/.a",
	"/tmp/xmr", "/tmp/config.json", "/var/tmp/config.json", "/dev/shm/config.json",
	"/tmp/secure.sh", "/tmp/auth.sh", "/usr/.work/work64",
}

// minerNameGlobs is the temp-name walk's -iname list: the globs are lowercase
// and the local walk lowercases the name it compares.
var minerNameGlobs = []string{
	"*xmrig*", "*minerd*", "*cpuminer*", "kworkerds*", "kdevtmpfsi*",
	"kinsing*", "watchbog*", "sustes*", "sysupdate*", "sysguard*",
	"networkservice*", "config.json",
}

// minerWalkDepth bounds the temp-name walk: the same -maxdepth the ssh script
// passes to find, so both channels stop at the same level.
const minerWalkDepth = 4

// minerScript hunts cryptominers in place: process lines matched out of a ps
// snapshot (grep -v drops this pipeline's own lines, which carry the pattern),
// attributes of the classic fixed drop paths, and a bounded name walk of the
// temp directories. That walk crosses devices — a service's PrivateTmp mounts a
// tmpfs inside /tmp — and is bounded by depth instead. Every arm is quiet when
// nothing matches; the deep time-clustered hunt stays with the mtime subcommand.
//
// The pattern and the three lists are the same ones the local tier walks, so
// the two channels hunt for identical things instead of two spellings of the
// same list drifting apart.
//
// Checks run concurrently, so on a clean host the ps check's snapshot still
// holds this script's own sh line, and the global known-malware-name /
// hidden-tmp-path rules light on it. Accepted: spelling the names plainly is
// worth one recognizable karma-owned line, and the split-quote trick to dodge
// it was reverted as unreadable. \b bounds every name so substrings stay out
// (macOS runs a legit daemon named networkserviceproxy).
var minerScript = fmt.Sprintf(`
pat='%s'
echo "== ps"
ps auxwwf | grep -aE "$pat" | grep -av grep
echo "== drop paths"
LC_ALL=C ls -l %s 2>/dev/null
echo "== temp names"
find %s -maxdepth %d -type f \( %s \) -exec ls -l {} + 2>/dev/null
`, minerPsSource, strings.Join(minerDropPaths, " "), strings.Join(tmpDirs, " "),
	minerWalkDepth, findNameArgs("-iname", minerNameGlobs))

// hidden-pids (atrk-style brute force, migrated 2026-10): a rootkit that
// filters the /proc readdir path still cannot hide from the kernel's own
// kill(pid, 0) existence check, so the two views are crossed. Both tiers
// print the same text: one scan context line, then a "hidden" section with
// one row per confirmed PID, so the rules fire on either tier. The native
// tier sweeps the whole pid space (pid_max is the kernel's own bound); the
// shell tier caps at 131072 because its interpreted loop probes at ~10µs per
// pid, so a full sweep would outlast the tier's deadline.

// hiddenPidsScript is the script branch of the same hunt — the branch the ssh
// channel runs. kill -0 is a shell builtin on every practical /bin/sh, so the
// brute-force loop forks nothing; the readdir views come from glob expansion,
// which is the getdents path a rootkit hooks.
const hiddenPidsScript = `
[ -d /proc/1 ] || exit 1
pidmax=$(cat /proc/sys/kernel/pid_max 2>/dev/null) || exit 1
case $pidmax in ''|*[!0-9]*) exit 1;; esac
cap=$pidmax
[ "$cap" -gt 131072 ] && cap=131072
echo "scan: pid_max=$pidmax scanned=1-$cap oracle=kill(pid,0) vs /proc readdir (threads included)"
[ "$(id -u)" = 0 ] || echo "note: not running as root: readdir may hide other users' processes"
norm=' '
for p in /proc/[0-9]*; do
  case $p in
    */[0-9]*) norm="$norm ${p##*/} ";;
  esac
done
for t in /proc/[0-9]*/task/[0-9]*; do
  case $t in
    */task/[0-9]*) norm="$norm ${t##*/} ";;
  esac
done
cand=' '
i=1
while [ "$i" -le "$cap" ]; do
  kill -0 "$i" 2>/dev/null && {
    case "$norm" in
      *" $i "*) ;;
      *) cand="$cand $i ";;
    esac
  }
  i=$((i + 1))
done
[ "$cand" = ' ' ] && exit 0
norm=' '
for p in /proc/[0-9]*; do
  case $p in
    */[0-9]*) norm="$norm ${p##*/} ";;
  esac
done
for t in /proc/[0-9]*/task/[0-9]*; do
  case $t in
    */task/[0-9]*) norm="$norm ${t##*/} ";;
  esac
done
out=
for i in $cand; do
  case "$norm" in
    *" $i "*) continue;;
  esac
  kill -0 "$i" 2>/dev/null || continue
  fd=no
  [ -e /proc/$i/fd ] && fd=yes
  comm=$(cat /proc/$i/comm 2>/dev/null)
  cmd=$(tr "\000" " " </proc/$i/cmdline 2>/dev/null)
  out="$out
PID $i  fd=$fd  comm=$comm  cmd='$cmd'"
done
[ -n "$out" ] && {
  echo "== hidden"
  echo "$out"
}
exit 0
`

// topHead and psSortHead are the row shapes the resource snapshot asks for:
// top's own table, and the two ps listings sorted by CPU and by memory.
const (
	topHead    = 25
	psSortHead = 10
)

// ProcessChecks covers processes.
var ProcessChecks = []*model.Check{
	// Locally every tier renders the in-process /proc snapshot (native_ps);
	// forest nesting is pstree's job there. On ssh the same labels run the
	// host binaries.
	define.LinuxCheck("ps", "Process tree", model.AspectProcess,
		[]model.Probe{
			{Label: "ps", Inv: model.Dual{Run: native.PsAux, Script: "ps auxwwf"}},
			{Label: "pstree", Inv: model.Dual{Run: native.Pstree, Script: "pstree -ap"}},
			{Label: "ps-ef", Inv: model.Dual{Run: native.PsEf, Script: "ps -ef"}},
		},
		define.CheckOpt{
			Syntax: model.SyntaxTable,
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
			// these caps are the shape each probe wants: plenty to read, and
			// small enough that a busy host's snapshot stays a panel
			{Label: "top", Inv: model.Dual{Run: native.Top, Script: "top -b -n 1"}, Head: topHead},
			{Label: "ps-cpu", Inv: model.Dual{Run: native.PsCPU, Script: "ps aux --sort=-%cpu"}, Head: psSortHead},
			{Label: "ps-mem", Inv: model.Dual{Run: native.PsMem, Script: "ps aux --sort=-%mem"}, Head: psSortHead},
		},
		define.CheckOpt{Syntax: model.SyntaxTop, Rules: []model.Rule{define.KeywordRule}}),
	define.LinuxCheck("proc-caps", "Session capability set (container escape surface)", model.AspectProcess,
		[]model.Probe{
			{Label: "caps", Inv: model.Dual{Run: native.ProcCaps(containerCgroupRe), Script: sessionCapsScript}, Adapt: native.DecodeCapMasks},
		},
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
		// The lsof tier is dual: locally native.DeletedExe ladders from lsof to
		// the /proc walk in one pass, so the two script-only tiers below exist
		// on the ssh channel alone — find covers the fd/cwd/exe links in one
		// process, the shell walk is the portable last resort for hosts whose
		// find has neither -lname nor -printf. lsof runs raw and is capped by
		// the reader's scan budget: a source-side line cap would cut the
		// stream before the keep filter sees the deleted rows.
		[]model.Probe{
			{Label: "lsof", Inv: model.Dual{Run: native.DeletedExe, Script: lsofScript}},
			{Label: "find", Inv: model.Dual{Script: findDeletedScript}, LineLimit: openScanLines},
			{Label: "proc-links", Inv: model.Dual{Script: deletedLinksScript}, LineLimit: openScanLines},
		},
		define.CheckOpt{
			// Keep only rows the kernel marked deleted; signal rows bypass keep
			// filters and are always kept.
			Filters: []model.LineFilter{
				model.NewFilter("deleted-lines", `\(deleted\)`, model.FilterKeep),
			},
		}),
	define.LinuxCheck("cwd-tmp", "Processes with cwd in a temp directory", model.AspectProcess,
		[]model.Probe{
			{Label: "proc-cwd", Inv: model.Dual{Run: native.CwdTmp(tmpDirs), Script: cwdTmpScript}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("proc-cwd-tmp", `^/proc/\d+ -> /(?:tmp|var/tmp|dev/shm)/\S*`, model.High,
					"process cwd is in a temp directory"),
			},
		}),
	define.LinuxCheck("hidden-procs", "proc vs ps process comparison", model.AspectProcess,
		[]model.Probe{
			{Label: "ps", Inv: model.Dual{Run: native.HiddenProcs, Script: hiddenProcsScript}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("proc-not-in-ps", `^[0-9]+$`, model.High,
					"in /proc but not in ps (or just exited)"),
			},
		}),
	define.LinuxCheck("hidden-pids", "Hidden process brute-force (kill(0) vs /proc)", model.AspectProcess,
		// Both branches print the same text shape, so the rules are shared.
		[]model.Probe{
			{Label: "brute", Inv: model.Dual{Run: native.HiddenPIDs, Script: hiddenPidsScript}, LineLimit: openScanLines},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("hidden-pid", `^PID \d+ `, model.Critical,
					"alive for the kernel, hidden from /proc listing"),
			},
		}),
	define.LinuxCheck("miner", "Cryptominer hunt (processes and drop paths)", model.AspectProcess,
		[]model.Probe{
			{Label: "scan", Inv: model.Dual{
				Run: native.Miner(native.MinerScan{
					Pattern:   minerPsPattern,
					DropPaths: minerDropPaths,
					NameGlobs: minerNameGlobs,
					TempDirs:  tmpDirs,
					MaxDepth:  minerWalkDepth,
				}),
				Script: minerScript,
			}, LineLimit: openScanLines},
		},
		define.CheckOpt{
			Syntax: model.SyntaxTable,
			// The drop-path and temp-name sections are ls -l shape, the ps section a
			// process table; one override per section keeps both colored
			SectionSyntax: []model.SectionSyntax{
				{Title: "drop paths", Syntax: model.SyntaxLsL},
				{Title: "temp names", Syntax: model.SyntaxLsL},
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
