// Package facts collects opening facts: capability probe + host info, one round trip.
//
// Linux and Windows each get a collector with aligned shapes: both fan out
// concurrently, and one failed path does not affect the remaining facts. Both probing
// and collection use the current logged-in user.
package facts

import (
	"cmp"
	"context"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/samber/lo"

	"karma/internal/fault"
	"karma/internal/model"
	"karma/internal/powershell"
	"karma/internal/regout"
	"karma/internal/session"
	"karma/internal/textutil"
)

// linuxFactBins are the binaries collect's own commands need; callers merge them into the capability probe list.
var linuxFactBins = []string{"hostname", "uname", "id"}

// windowsFactBins are the binaries collect_windows's own commands need; callers merge them into the capability probe list.
var windowsFactBins = []string{"powershell", "reg"}

// Fact budgets: the capability probe searches PATH once per name, and one host
// fact is a single small command whose output the header shows. Both are this
// package's policy, stated where the call is made.
const (
	factProbeBudget = 15 * time.Second
	factBudget      = 10 * time.Second
)

const hostnameScript = "hostname 2>/dev/null || cat /proc/sys/kernel/hostname"

const (
	currentVersionPS  = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
	currentVersionReg = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	computerNameReg   = `HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`
	volatileEnvReg    = `HKCU\Volatile Environment`
)

var (
	prettyNameRe = regexp.MustCompile(`(?m)^PRETTY_NAME="?([^"\n]+)"?`)
)

// windowsFactsScript brings back all host facts in one cold start when PS is present:
// sectioned output; when CurrentVersion cannot be read the os/kernel sections emit no
// headings and fall back to their own defaults.
var windowsFactsScript = strings.Join([]string{
	"$v = Get-ItemProperty '" + currentVersionPS + "' -ErrorAction SilentlyContinue",
	"'== host'; $env:COMPUTERNAME",
	`'== user'; "$env:USERDOMAIN\$env:USERNAME"`,
	"if ($v) {",
	"  '== os'; $v.ProductName + ' ' + $v.DisplayVersion",
	"  '== kernel'; $v.CurrentVersion + '.' + $v.CurrentBuildNumber + '.' + $v.UBR",
	"}",
}, "\n")

// CollectFor dispatches fact collection: Windows always collects through a
// session (its facts come from PowerShell and the registry); Linux collects
// in process on the local channel and over the session everywhere else.
func CollectFor(ctx context.Context, platform model.Platform, sess session.Session, bins []string) model.HostFacts {
	switch {
	case platform == model.Windows:
		return CollectWindows(ctx, sess, bins)
	case sess.Channel() == model.ChanLocal:
		return collectLocal(bins)
	default:
		return Collect(ctx, sess, bins)
	}
}

// Collect concurrently gathers binary presence and host facts (Linux directory).
func Collect(ctx context.Context, sess session.Session, bins []string) model.HostFacts {
	names := probeBins(bins, linuxFactBins)
	results := gather(ctx, map[string]func(context.Context) model.RunResult{
		"bins": func(ctx context.Context) model.RunResult {
			return runShell(ctx, sess, binProbe(names), factProbeBudget)
		},
		"hostname": func(ctx context.Context) model.RunResult { return runShell(ctx, sess, hostnameScript, factBudget) },
		"kernel": func(ctx context.Context) model.RunResult {
			return call(ctx, sess, model.NewCommand("uname", "-r"), factBudget)
		},
		"os": func(ctx context.Context) model.RunResult {
			return runShell(ctx, sess, "cat /etc/os-release", factBudget)
		},
		"uid": func(ctx context.Context) model.RunResult {
			return call(ctx, sess, model.NewCommand("id", "-u"), factBudget)
		},
	})
	return model.HostFacts{
		AvailableBins: availableBins(results["bins"].Stdout, names),
		Hostname:      firstLine(results["hostname"].Stdout, "unknown"),
		Kernel:        firstLine(results["kernel"].Stdout, ""),
		OsPretty:      prettyName(results["os"].Stdout),
		UID:           parseUID(results["uid"].Stdout),
		ProbeCut:      results["bins"].Verdict == model.VerdictTimedOut,
	}
}

// CollectWindows is the same-shaped collection on the Windows side, with a two-step
// capability probe.
//
// The first step probes via PowerShell and, when PS is present, collects all facts;
// when PS is absent (XP/2003/nano systems) the second step directly execs `reg`
// (not through a shell) and takes facts from the registry instead -- so the registry
// checks' fallback tier stays available as usual, and PS-only checks are skipped as
// usual for "missing powershell".
func CollectWindows(ctx context.Context, sess session.Session, bins []string) model.HostFacts {
	names := probeBins(bins, windowsFactBins)
	probe := runPS(ctx, sess, probeScript(names), factProbeBudget)
	available := availableBins(probe.Stdout, names)

	if available["powershell"] {
		// one PS cold start brings back all facts; the four paths are evaluated eagerly, 15s is the grace
		values := labeledLines(runPS(ctx, sess, windowsFactsScript, factProbeBudget).Stdout)
		return model.HostFacts{
			AvailableBins: available,
			Hostname:      cmp.Or(values["host"], "unknown"),
			Kernel:        values["kernel"],
			OsPretty:      cmp.Or(values["os"], "unknown version"),
			UID:           -1,
			User:          values["user"],
			ProbeCut:      probe.Verdict == model.VerdictTimedOut,
		}
	}

	// PS absent: reg direct probe + registry facts. One CurrentVersion key fetches
	// ProductName/CurrentVersion/CurrentBuildNumber/UBR/DisplayVersion
	results := gather(ctx, map[string]func(context.Context) model.RunResult{
		"version": func(ctx context.Context) model.RunResult {
			return call(ctx, sess, model.NewCommand("reg", "query", currentVersionReg), factBudget)
		},
		"hostname": func(ctx context.Context) model.RunResult {
			return call(ctx, sess, model.NewCommand("reg", "query", computerNameReg, "/v", "ComputerName"), factBudget)
		},
		"username": func(ctx context.Context) model.RunResult {
			return call(ctx, sess, model.NewCommand("reg", "query", volatileEnvReg, "/v", "USERNAME"), factBudget)
		},
	})
	version := results["version"]
	if version.Verdict == model.VerdictAnswered {
		available = withBin(available, "reg")
	}
	values := regValueMap(version.Stdout)
	kernel := strings.Join(lo.Compact([]string{
		values["CurrentVersion"],
		values["CurrentBuildNumber"],
		regDword(values["UBR"]),
	}), ".")
	return model.HostFacts{
		AvailableBins: available,
		Hostname:      regLastData(results["hostname"].Stdout, "unknown"),
		Kernel:        kernel,
		OsPretty:      cmp.Or(strings.TrimSpace(values["ProductName"]+" "+values["DisplayVersion"]), "unknown version"),
		UID:           -1,
		User:          regLastData(results["username"].Stdout, ""),
		ProbeCut:      probe.Verdict == model.VerdictTimedOut,
	}
}

func runShell(ctx context.Context, sess session.Session, script string, budget time.Duration) model.RunResult {
	return call(ctx, sess, model.Shell{Script: script}, budget)
}

func runPS(ctx context.Context, sess session.Session, script string, budget time.Duration) model.RunResult {
	return call(ctx, sess, powershell.PowerShell(script), budget)
}

// call runs one fact's invocation under a budget of its own: the header is
// assembled before any check runs, so a target that stalls here must not hold
// the run up.
func call(ctx context.Context, sess session.Session, inv model.Invocation, budget time.Duration) model.RunResult {
	ctx, cancel := session.Within(ctx, budget)
	defer cancel()
	return sess.Run(ctx, model.Call{Inv: inv})
}

// gather runs all fact collection concurrently, keyed by job name so a result can
// never drift onto the wrong fact; a failed path falls back to an empty answer.
// A job that panics fails that one fact (fault.Result) rather than ending the
// run: a fact is one line of the header, and the checks matter more than it.
func gather(ctx context.Context, jobs map[string]func(context.Context) model.RunResult) map[string]model.RunResult {
	results := make(map[string]model.RunResult, len(jobs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, job := range jobs {
		wg.Go(func() {
			result, damage := fault.Result("host fact "+name, func() model.RunResult { return job(ctx) })
			if damage != nil {
				result = model.RunResult{Verdict: model.VerdictFailed, Stderr: damage.Error(), ExitCode: -1}
			}
			mu.Lock()
			defer mu.Unlock()
			results[name] = result
		})
	}
	wg.Wait()
	return results
}

// probeBins unions, sorts and dedupes the probe list; caller-supplied check dependencies come first, this package's own after.
func probeBins(bins, extra []string) []string {
	names := slices.Concat(bins, extra)
	slices.Sort(names)
	return slices.Compact(names)
}

// binProbe: dash's command -v only recognizes the first name, so probe one by one for portability.
func binProbe(names []string) string {
	words := lo.Map(names, func(name string, _ int) string { return "'" + name + "'" })
	return "for name in " + strings.Join(words, " ") + "; do command -v \"$name\" 2>/dev/null || true; done"
}

// probeScript is the PowerShell capability probe: Get-Command names each one, and those present report in.
func probeScript(names []string) string {
	words := lo.Map(names, func(name string, _ int) string { return "'" + name + "'" })
	return "foreach ($n in " + strings.Join(words, ", ") + ") {" +
		" if (Get-Command $n -ErrorAction SilentlyContinue) { $n } }"
}

// availableBins reads capability probe output lines: absolute paths or builtin names;
// both POSIX and Windows path separators are recognized.
func availableBins(stdout string, wanted []string) map[string]bool {
	set := lo.SliceToMap(wanted, func(name string) (string, bool) { return name, false })
	for line := range textutil.Lines(stdout) {
		parts := strings.FieldsFunc(line, func(r rune) bool { return r == '/' || r == '\\' })
		if name := lo.LastOr(parts, ""); name != "" {
			if _, ok := set[name]; ok {
				set[name] = true
			}
		}
	}
	return set
}

func withBin(bins map[string]bool, name string) map[string]bool {
	out := maps.Clone(bins)
	out[name] = true
	return out
}

// labeledLines collapses `== title` sectioned output into a map: each section takes its first non-empty line.
func labeledLines(stdout string) map[string]string {
	out := map[string]string{}
	title := ""
	for line := range textutil.Lines(stdout) {
		if head, ok := strings.CutPrefix(line, "== "); ok {
			title = strings.TrimSpace(head)
			continue
		}
		text := strings.TrimSpace(line)
		if title == "" || text == "" {
			continue
		}
		if _, seen := out[title]; !seen {
			out[title] = text
		}
	}
	return out
}

// regValueMap collapses `name type data` value lines in reg query output into a map.
func regValueMap(stdout string) map[string]string {
	out := make(map[string]string)
	for _, value := range regout.ParseRegValues(stdout) {
		out[value.Name] = value.Data
	}
	return out
}

// regLastData reads /v single-value query output: the data field of the last value line.
func regLastData(stdout, fallback string) string {
	return cmp.Or(lo.LastOr(regout.ParseRegValues(stdout), regout.Value{}).Data, fallback)
}

// regDword: reg's DWORD is 0x-prefixed hex; convert to decimal. Returns a non-0x
// prefix as-is, and returns an empty string for a 0x prefix that fails to parse
// (lo.Compact drops empty components from the join).
func regDword(raw string) string {
	if !strings.HasPrefix(raw, "0x") {
		return raw
	}
	value, err := strconv.ParseUint(raw[2:], 16, 64)
	if err != nil {
		return ""
	}
	return strconv.FormatUint(value, 10)
}

// firstLine is the first line of output; empty output gives the fallback.
func firstLine(stdout, fallback string) string {
	head, _, _ := strings.Cut(strings.TrimSpace(stdout), "\n")
	return cmp.Or(head, fallback)
}

func prettyName(osRelease string) string {
	if matched := prettyNameRe.FindStringSubmatch(osRelease); matched != nil {
		return matched[1]
	}
	return "unknown distro"
}

func parseUID(stdout string) int {
	value, err := strconv.Atoi(strings.TrimSpace(stdout))
	if err != nil {
		return -1
	}
	return value
}
