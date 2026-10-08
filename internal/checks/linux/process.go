// process: the process listing and the tree the parent links make of it, the
// session capability set (container escape surface), and a cryptominer hunt.

package linux

import (
	"regexp"
	"strconv"
	"strings"

	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/form"
	"karma/internal/model"
	"karma/internal/script"
)

// psServiceAccounts is the account column's web-service names, and psInterpreter
// the interpreters a service account has no business spawning: the two halves of
// the webshell rule, stated where the rule reads them.
var psServiceAccounts = []string{"www-data", "wwwrun", "apache", "nginx", "nobody"}

var psInterpreter = regexp.MustCompile(`\b(?:(?:ba|z|da|k)?sh|python[0-9.]*|perl|ruby|nc|socat)\b`)

// psTable is the process listing's shape: a table, with the numeric columns
// right-aligned the way ps prints them. The declaration is keyed by column name
// because the checks that read it print different columns — ps -ef's eight,
// top's aux rows of eleven — and all of them read right against one table.
var psTable = form.Table{
	Align: map[string]form.Alignment{
		"PID": form.Right, "%CPU": form.Right, "%MEM": form.Right, "VSZ": form.Right,
		"RSS": form.Right, "START": form.Right, "TIME": form.Right,
		"PPID": form.Right, "C": form.Right, "STIME": form.Right,
	},
}

// containerMarkers is the ERE that recognizes a container's cgroup scope, whose
// runtimes each spell their own scope name. One string feeds both readings: the
// script's grep over /proc/1/cgroup and the local RE2 compiled from it, so the
// two cannot drift apart.
const containerMarkers = `(docker|containerd|kubepods|libpod|lxc|kata)[/.-]`

// containerCgroupRe is containerMarkers as the local read's pattern.
var containerCgroupRe = regexp.MustCompile(`(?i)` + containerMarkers)

// containerCheck is the shell's own container test: /.dockerenv (Docker),
// /run/.containerenv (Podman), the PID 1 cgroup path (the runtimes
// containerMarkers names), and systemd-detect-virt. It is one constant because
// every surface of the capability tier asks it for itself.
const containerCheck = `[ -f /.dockerenv ] || [ -f /run/.containerenv` +
	` || grep -qaE "` + containerMarkers + `" /proc/1/cgroup 2>/dev/null` +
	` || systemd-detect-virt --container >/dev/null 2>&1`

// capsContextScript is the session's context line: inside a container the
// capability set is the standing escape surface, on the host it is fixed by the
// login uid (root shows the full set by definition), so the line is the whole
// answer there.
const capsContextScript = `
if ` + containerCheck + `; then
  echo "context: container"
else
  echo "context: host"
fi
`

// capsCapshScript is the capability table as capsh prints it, inside a container
// alone: outside one the surface answers 127, the way a missing binary does, and
// the section is simply not there. capsh (libcap2-bin, near-universal) decodes
// the names.
const capsCapshScript = `
` + containerCheck + ` || exit 127
command -v capsh >/dev/null 2>&1 || exit 127
capsh --print 2>/dev/null
`

// capsStatusScript is the same set read from the /proc/self/status masks, which
// the check's own adapt (native.DecodeCapMasks) decodes — the fallback where
// capsh is absent.
const capsStatusScript = `
` + containerCheck + ` || exit 127
command -v capsh >/dev/null 2>&1 && exit 127
grep "^Cap" /proc/self/status 2>/dev/null
`

// procCapsTier is the capability check's surfaces: the context line, then
// whichever table the session can answer with.
func procCapsTier() []model.Step {
	return surfacesTier("caps", native.DecodeCapMasks, []surface{
		{Title: "", Native: native.CapsContext(containerCgroupRe), Script: capsContextScript},
		{Title: "capsh --print", Native: native.CapsCapsh(containerCgroupRe), Script: capsCapshScript},
		{Title: "/proc/self/status", Native: native.CapsStatus(containerCgroupRe), Script: capsStatusScript},
	})
}

// tmpGlobs is tmpDirs as the shell case pattern the cwd walk matches: every temp
// directory and everything below it.
var tmpGlobs = func() string {
	globs := make([]string, len(tmpDirs))
	for index, dir := range tmpDirs {
		globs[index] = dir + "/*"
	}
	return strings.Join(globs, "|")
}()

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
  case "$t" in *\(deleted\)) printf '%s -> %s\n' "${l#` + script.ProcPrefix + `}" "$t";; esac
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
// shell walk covers, doing every lstat in-process instead of one readlink fork
// per link. -lname matches the kernel's "(deleted)" link-target suffix.
// -lname/-printf are GNU extensions: a find without them fails the probe and
// the chain falls through to the walk. ProcPathStrip cuts the /proc prefix, so
// the rows match the walk's.
const findDeletedScript = `find /proc/[0-9]*/exe /proc/[0-9]*/cwd /proc/[0-9]*/fd` +
	` -maxdepth 1 -lname '*(deleted)' -printf '%p -> %l\n' 2>/dev/null | sed 's|^` + script.ProcPrefix + `||'`

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

// minerTier is the hunt's three surfaces: the process lines matched out of a ps
// snapshot, the attributes of the classic fixed drop paths, and the bounded name
// walk of the temp directories. Every arm is quiet when nothing matches; the deep
// time-clustered hunt stays with the mtime subcommand.
//
// The pattern and the three lists are the same ones the in-process tier walks, so
// both sources hunt for identical things instead of two spellings of the same
// list drifting apart. The section titles are what the check's per-section syntax
// reads, so each surface keeps its own.
func minerTier() []model.Step {
	scan := native.MinerScan{
		Pattern:   minerPsPattern,
		DropPaths: minerDropPaths,
		NameGlobs: minerNameGlobs,
		TempDirs:  tmpDirs,
		MaxDepth:  minerWalkDepth,
	}
	return surfacesTier("scan", nil, []surface{
		{Title: "ps", Native: native.MinerProcesses(scan), Script: minerPsScript, Cap: model.Scan(openScanLines)},
		{Title: "drop paths", Native: native.MinerDropPaths(scan), Script: minerDropPathsScript, Cap: model.Scan(openScanLines)},
		{Title: "temp names", Native: native.MinerTempNames(scan), Script: minerTempNamesScript, Cap: model.Scan(openScanLines)},
	})
}

// minerPsScript matches the process lines out of a ps snapshot; grep -v drops
// this pipeline's own lines, which carry the pattern.
var minerPsScript = `pat='` + minerPsSource + `'
ps auxwwf | grep -aE "$pat" | grep -av grep
`

// minerDropPathsScript reads the attributes of the fixed drop paths.
var minerDropPathsScript = "LC_ALL=C ls -l " + strings.Join(minerDropPaths, " ") + " 2>/dev/null\n"

// minerTempNamesScript walks the temp directories by name, bounded by depth:
// the walk crosses devices on purpose — a service's PrivateTmp mounts a tmpfs
// inside /tmp.
var minerTempNamesScript = "find " + strings.Join(tmpDirs, " ") +
	" -maxdepth " + strconv.Itoa(minerWalkDepth) + " -type f \\( " +
	findNameArgs("-iname", minerNameGlobs) + " \\) -exec ls -l {} + 2>/dev/null\n"

// findNameArgs renders a find name test alternation: one -name/-iname word per
// pattern, joined by -o.
func findNameArgs(option string, patterns []string) string {
	words := make([]string, len(patterns))
	for index, pattern := range patterns {
		words[index] = option + " '" + pattern + "'"
	}
	return strings.Join(words, " -o ")
}

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
// passes to find, so both sources stop at the same level.
const minerWalkDepth = 4

// hidden-pids (atrk-style brute force): a rootkit that filters the /proc
// readdir path still cannot hide from the kernel's own kill(pid, 0) existence
// check, so the two views are crossed. Both tiers print the same text: one scan
// context line, then one row per confirmed PID, so the rules fire on either
// tier. The native tier sweeps the whole pid space (pid_max is the kernel's own
// bound); the sh tier caps at 131072 because its interpreted loop probes at
// ~10µs per pid, so a full sweep would outlast the tier's deadline.

// psSortHead is the row shape the resource snapshot asks for: each of the two
// sorted ps listings is a panel of its own, and ten rows answer "what is using
// the box" without becoming the whole process table.
const psSortHead = 10

// hiddenPidsScript is the sh source's brute force over the same two views: kill
// -0 is a shell builtin on every practical /bin/sh, so the loop forks nothing,
// and the readdir views come from glob expansion — the getdents path a rootkit
// hooks. normtable fills $norm with both views (pids and their threads); the two
// passes of the difference read the same table, so only a process one view
// genuinely drops can be a candidate. It caps the sweep at 131072 because its
// interpreted loop probes at ~10µs per pid, so a full pid space would outlast the
// tier's deadline; the in-process tier sweeps pid_max itself.
const hiddenPidsScript = `
[ -d /proc/1 ] || exit 1
pidmax=$(cat /proc/sys/kernel/pid_max 2>/dev/null) || exit 1
case $pidmax in ''|*[!0-9]*) exit 1;; esac
cap=$pidmax
[ "$cap" -gt 131072 ] && cap=131072
echo "scan: pid_max=$pidmax scanned=1-$cap oracle=kill(pid,0) vs /proc readdir (threads included)"
[ "$(id -u)" = 0 ] || echo "note: not running as root: readdir may hide other users' processes"
normtable() {
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
}
normtable
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
normtable
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
[ -n "$out" ] && echo "$out"
exit 0
`

// pstreeTree is the process tree's shape: the ppid link nests the nodes, and a
// node draws the process's identity and its command line. The account travels
// with every record for the rules to read; the tree's own line does not carry
// it, so a rule that names it paints the node whole.
var pstreeTree = form.Tree{ID: "PID", Parent: "PPID", Label: []string{"PID", "CMD"}}

// processRules judge one row of a process listing. The table and the tree read
// the same fields — the account and the command line — so one list serves both,
// and a finding reads the same whichever shape the check is drawn in.
var processRules = []model.Matcher{
	// The command line is one field, so the pattern runs over its value: a
	// temp path at the value's start or after a blank is the finding, in
	// whichever column holds it.
	model.NewRule("ps-tmp-path", `(?:^|\s)/(?:tmp|var/tmp|dev/shm)/\S*`, model.Medium,
		"command line references temp path"),
	// A web service account spawning a shell/interpreter is webshell execution in
	// progress; normal web process names (php-fpm, httpd, gunicorn) do not contain
	// these words. The selection names both spellings of each column — auxww's
	// USER and COMMAND, System V's UID and CMD — and the conjunction paints the
	// account cell and the interpreter word, nothing between them.
	model.NewJudged("ps-service-shell", model.Medium,
		"service account running a shell/interpreter (typical webshell execution)",
		model.All{
			model.FieldOneOf{Fields: []string{"USER", "UID"}, Values: psServiceAccounts},
			model.FieldRegex{Fields: []string{"COMMAND", "CMD"}, Pattern: psInterpreter},
		}),
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
}

// ProcessChecks covers processes.
var ProcessChecks = []*model.Check{
	// One command, two sources: the native tier states `ps -ef`'s System V
	// fields from /proc, and the sh tier runs the target's own ps and parses
	// the same schema out of it. A run walks one of them (the source it was
	// asked for), never both. The table is flat — one row per process —
	// because the hierarchy is the pstree check's business.
	define.LinuxCheck("ps", "Process table", model.AspectProcess,
		[]model.Step{
			{{Label: "ps", Inv: model.Fields{Read: native.PsEf}}},
			{{Label: "ps-ef", Inv: psEfScript}},
		},
		model.Options{Form: psTable, Rules: processRules}),
	// The same records, drawn as the tree the ppid links make of them: either
	// source hands the parent link over and the form nests the nodes.
	define.LinuxCheck("pstree", "Process tree", model.AspectProcess,
		[]model.Step{
			{{Label: "pstree", Inv: model.Fields{Read: native.PsEf}}},
			{{Label: "pstree-ef", Inv: psEfScript}},
		},
		model.Options{Form: pstreeTree, Rules: processRules}),
	// The resource snapshot is the two sorted aux views, and nothing else, on
	// either source: procps' own top prints a near-zero %CPU delta on its first
	// frame (it compares against a reading taken at startup), so the order that
	// answers the question comes from a ps listing — karma reads /proc itself on
	// the local channel, and the sh source runs the target's own ps through the
	// parser that states the same fields. Each source's two views are one step,
	// so a panel carries the CPU order and then the memory order.
	define.LinuxCheck("top", "Resource usage snapshot", model.AspectProcess,
		[]model.Step{
			{
				{Label: "ps-cpu", Inv: model.Fields{Read: native.PsCPU}, Cap: model.Shape(psSortHead)},
				{Label: "ps-mem", Inv: model.Fields{Read: native.PsMem}, Cap: model.Shape(psSortHead)},
			},
			{
				{Label: "ps-cpu-sh", Inv: psAuxScript("ps", "auxww", "--sort=-%cpu"), Cap: model.Shape(psSortHead)},
				{Label: "ps-mem-sh", Inv: psAuxScript("ps", "auxww", "--sort=-%mem"), Cap: model.Shape(psSortHead)},
			},
		},
		model.Options{
			// Both sources state these rows as fields, so the ps check's table
			// draws them the way it draws ps -ef's.
			Form:  psTable,
			Rules: []model.Matcher{define.KeywordRule},
		}),
	define.LinuxCheck("proc-caps", "Session capability set (container escape surface)", model.AspectProcess,
		procCapsTier(),
		model.Options{
			Rules: []model.Matcher{
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
		// One native tier: native.DeletedExe runs the host's lsof when it exists and
		// otherwise walks the /proc exe, cwd and fd links itself, which needs
		// neither -lname nor -printf. lsof runs raw and is capped by the
		// reader's scan budget: a source-side line cap would cut the stream
		// before the keep filter sees the deleted rows.
		[]model.Step{
			{{Label: "lsof", Inv: model.Native{Body: native.DeletedExe}}},
			// The sh source's three readings of the same link tree, in the order
			// that costs least: lsof, one find over the links, and the portable
			// readlink walk for hosts whose find has neither -lname nor -printf.
			{{Label: "lsof-sh", Inv: model.Sh(lsofScript)}},
			{{Label: "find-sh", Inv: model.Sh(findDeletedScript), Cap: model.Scan(openScanLines)}},
			{{Label: "proc-links-sh", Inv: model.Sh(deletedLinksScript), Cap: model.Scan(openScanLines)}},
		},
		model.Options{
			// Keep only rows the kernel marked deleted; signal rows bypass keep
			// filters and are always kept.
			Filters: []model.LineFilter{
				model.NewFilter("deleted-lines", `\(deleted\)`, model.FilterKeep),
			},
		}),
	define.LinuxCheck("cwd-tmp", "Processes with cwd in a temp directory", model.AspectProcess,
		[]model.Step{
			{{Label: "proc-cwd", Inv: model.Native{Body: native.CwdTmp(tmpDirs)}}},
			{{Label: "proc-cwd-sh", Inv: model.Sh(cwdTmpScript)}},
		},
		model.Options{
			Rules: []model.Matcher{
				model.NewRule("proc-cwd-tmp", `^/proc/\d+ -> /(?:tmp|var/tmp|dev/shm)/\S*`, model.High,
					"process cwd is in a temp directory"),
			},
		}),
	define.LinuxCheck("hidden-procs", "proc vs ps process comparison", model.AspectProcess,
		[]model.Step{
			{{Label: "ps", Inv: model.Native{Body: native.HiddenProcs}}},
			{{Label: "ps-sh", Inv: model.Sh(hiddenProcsScript)}},
		},
		model.Options{
			Rules: []model.Matcher{
				model.NewRule("proc-not-in-ps", `^[0-9]+$`, model.High,
					"in /proc but not in ps (or just exited)"),
			},
		}),
	define.LinuxCheck("hidden-pids", "Hidden process brute-force (kill(0) vs /proc)", model.AspectProcess,
		// Both readings print the same text shape, so the rules are shared.
		[]model.Step{
			{{Label: "brute", Inv: model.Native{Body: native.HiddenPIDs}, Cap: model.Scan(openScanLines)}},
			{{Label: "brute-sh", Inv: model.Sh(hiddenPidsScript), Cap: model.Scan(openScanLines)}},
		},
		model.Options{
			Rules: []model.Matcher{
				model.NewRule("hidden-pid", `^PID \d+ `, model.Critical,
					"alive for the kernel, hidden from /proc listing"),
			},
		}),
	define.LinuxCheck("miner", "Cryptominer hunt (processes and drop paths)", model.AspectProcess,
		minerTier(),
		model.Options{
			Syntax: model.SyntaxTable,
			// The drop-path and temp-name sections are ls -l shape, the ps section a
			// process table; one override per section keeps both colored
			SectionSyntax: []model.SectionSyntax{
				{Title: "drop paths", Syntax: model.SyntaxLsL},
				{Title: "temp names", Syntax: model.SyntaxLsL},
			},
			Rules: []model.Matcher{
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
