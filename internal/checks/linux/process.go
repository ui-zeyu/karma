// process: the process listing and the tree the parent links make of it, the
// session capability set (container escape surface), and a cryptominer hunt.

package linux

import (
	"regexp"
	"strings"

	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/form"
	"karma/internal/model"
)

// psServiceAccounts is the account column's web-service names, and psInterpreter
// the interpreters a service account has no business spawning: the two halves of
// the webshell rule, stated where the rule reads them.
var psServiceAccounts = []string{"www-data", "wwwrun", "apache", "nginx", "nobody"}

var psInterpreter = regexp.MustCompile(`\b(?:(?:ba|z|da|k)?sh|python[0-9.]*|perl|ruby|nc|socat)\b`)

// psTable is the /proc snapshot's shape: a table, with the numeric columns
// right-aligned the way ps prints them. The declaration is keyed by column name
// because the tiers print different columns (auxww's eleven, System V's eight)
// and both read right against one table.
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

// hidden-pids (atrk-style brute force): a rootkit that filters the /proc
// filters the /proc readdir path still cannot hide from the kernel's own
// kill(pid, 0) existence check, so the two views are crossed. Both tiers
// print the same text: one scan context line, then a "hidden" section with
// one row per confirmed PID, so the rules fire on either tier. The native
// tier sweeps the whole pid space (pid_max is the kernel's own bound); the
// shell tier caps at 131072 because its interpreted loop probes at ~10µs per
// pid, so a full sweep would outlast the tier's deadline.

// topHead and psSortHead are the row shapes the resource snapshot asks for:
// top's own table, and the two ps listings sorted by CPU and by memory.
const (
	topHead    = 25
	psSortHead = 10
)

// pstreeTree is the process tree's shape: the ppid link nests the nodes, and a
// node draws the process's identity and its command line. The account travels
// with every record for the rules to read; the tree's own line does not carry
// it, so a rule that names it paints the node whole.
var pstreeTree = form.Tree{ID: "PID", Parent: "PPID", Label: []string{"PID", "COMMAND"}}

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
	// Two probes read the same /proc snapshot: auxww's eleven columns, and
	// System V's eight as the fallback. Both state their fields, so no tier
	// here hands the panel text to read back. The table is flat — one row per
	// process — because the hierarchy is the pstree check's business.
	define.LinuxCheck("ps", "Process table", model.AspectProcess,
		[]model.Step{
			{{Label: "ps", Inv: model.Fields{Read: native.PsAux}}},
			{{Label: "ps-ef", Inv: model.Fields{Read: native.PsEf}}},
		},
		define.CheckOpt{Form: psTable, Rules: processRules}),
	// The same snapshot, drawn as the tree the ppid links make of it: the tier
	// hands the parent link over and the form nests the nodes.
	define.LinuxCheck("pstree", "Process tree", model.AspectProcess,
		[]model.Step{{{Label: "pstree", Inv: model.Fields{Read: native.Pstree}}}},
		define.CheckOpt{Form: pstreeTree, Rules: processRules}),
	define.LinuxCheck("top", "Resource usage snapshot", model.AspectProcess,
		[]model.Step{
			{ // these caps are the shape each probe wants: plenty to read, and
				// small enough that a busy host's snapshot stays a panel
				{Label: "top", Inv: model.Native{Body: native.Top}, Cap: model.Shape(topHead)}},
			{{Label: "ps-cpu", Inv: model.Fields{Read: native.PsCPU}, Cap: model.Shape(psSortHead)}},
			{{Label: "ps-mem", Inv: model.Fields{Read: native.PsMem}, Cap: model.Shape(psSortHead)}},
		},
		define.CheckOpt{
			Syntax: model.SyntaxTop,
			// top's own table is the tool's text; the two ps --sort tiers state the
			// same fields the ps check draws, and land in the same table.
			Form:  psTable,
			Rules: []model.Matcher{define.KeywordRule},
		}),
	define.LinuxCheck("proc-caps", "Session capability set (container escape surface)", model.AspectProcess,
		[]model.Step{{{Label: "caps", Inv: model.Native{Body: native.ProcCaps(containerCgroupRe)}, Adapt: native.DecodeCapMasks}}},
		define.CheckOpt{
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
		// One tier: native.DeletedExe runs the host's lsof when it exists and
		// otherwise walks the /proc exe, cwd and fd links itself, which needs
		// neither -lname nor -printf. lsof runs raw and is capped by the
		// reader's scan budget: a source-side line cap would cut the stream
		// before the keep filter sees the deleted rows.
		[]model.Step{
			{{Label: "lsof", Inv: model.Native{Body: native.DeletedExe}}},
		},
		define.CheckOpt{
			// Keep only rows the kernel marked deleted; signal rows bypass keep
			// filters and are always kept.
			Filters: []model.LineFilter{
				model.NewFilter("deleted-lines", `\(deleted\)`, model.FilterKeep),
			},
		}),
	define.LinuxCheck("cwd-tmp", "Processes with cwd in a temp directory", model.AspectProcess,
		[]model.Step{{{Label: "proc-cwd", Inv: model.Native{Body: native.CwdTmp(tmpDirs)}}}},
		define.CheckOpt{
			Rules: []model.Matcher{
				model.NewRule("proc-cwd-tmp", `^/proc/\d+ -> /(?:tmp|var/tmp|dev/shm)/\S*`, model.High,
					"process cwd is in a temp directory"),
			},
		}),
	define.LinuxCheck("hidden-procs", "proc vs ps process comparison", model.AspectProcess,
		[]model.Step{{{Label: "ps", Inv: model.Native{Body: native.HiddenProcs}}}},
		define.CheckOpt{
			Rules: []model.Matcher{
				model.NewRule("proc-not-in-ps", `^[0-9]+$`, model.High,
					"in /proc but not in ps (or just exited)"),
			},
		}),
	define.LinuxCheck("hidden-pids", "Hidden process brute-force (kill(0) vs /proc)", model.AspectProcess,
		// Both branches print the same text shape, so the rules are shared.
		[]model.Step{{{Label: "brute", Inv: model.Native{Body: native.HiddenPIDs}, Cap: model.Scan(openScanLines)}}},
		define.CheckOpt{
			Rules: []model.Matcher{
				model.NewRule("hidden-pid", `^PID \d+ `, model.Critical,
					"alive for the kernel, hidden from /proc listing"),
			},
		}),
	define.LinuxCheck("miner", "Cryptominer hunt (processes and drop paths)", model.AspectProcess,
		[]model.Step{{{Label: "scan", Inv: model.Native{Body: native.Miner(native.MinerScan{
			Pattern:   minerPsPattern,
			DropPaths: minerDropPaths,
			NameGlobs: minerNameGlobs,
			TempDirs:  tmpDirs,
			MaxDepth:  minerWalkDepth,
		})}, Cap: model.Scan(openScanLines)}}},
		define.CheckOpt{
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
