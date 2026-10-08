// system: basic facts: distro and kernel, boot time, clock, environment variables.

package linux

import (
	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/form"
	"karma/internal/model"
	"karma/internal/shape"
)

// osReleaseSh is the sh source's reading of the distro and kernel facts: the
// file when the target has it, the LSB tool when it does not, and uname's own
// line either way — the same three surfaces native.OsRelease reads.
const osReleaseSh = `cat /etc/os-release 2>/dev/null || lsb_release -a 2>/dev/null; echo; uname -a`

// freeCheck is the memory reading, from /proc/meminfo here and from the
// target's own free -h over a channel. The human spelling is the tool's default
// reading of the file — the same KiB figures scaled for the reader — so the sh
// source runs the tool's own -h and the local tier scales the file itself
// (native.Free states which procps version's digits an old host prints instead).
func freeCheck() []model.Step {
	return []model.Step{
		{{Label: "free", Inv: model.Native{Body: native.Free}}},
		{{Label: "free-sh", Inv: model.Sh("free -h")}},
	}
}

// SystemChecks covers system information.
var SystemChecks = []*model.Check{
	define.LinuxCheck("os-release", "Distro and kernel", model.AspectSystem,
		[]model.Step{
			{{Label: "cat", Inv: model.Native{Body: native.OsRelease}}},
			{{Label: "os-release-sh", Inv: model.Sh(osReleaseSh)}},
		},
		// The file's KEY=VALUE lines are its own two columns; the sh source's
		// lsb_release fallback is not this table and stays the text it wrote.
		model.Options{Form: form.Table{}, Normalize: shape.OsRelease}),
	define.LinuxCheck("uptime", "Hostname and boot time", model.AspectSystem,
		[]model.Step{
			{{Label: "uptime", Inv: model.Native{Body: native.Uptime}}},
			{{Label: "proc-uptime", Inv: model.Native{Body: native.ProcUptime}}},
			// The sh source's two readings of the same facts: the tool that
			// prints the banner, and the file the banner is derived from.
			{{Label: "uptime-sh", Inv: model.Sh("uptime")}},
			{{Label: "proc-uptime-sh", Inv: model.Sh("cat /proc/uptime")}},
		},
		model.Options{}),
	define.LinuxCheck("free", "Memory and swap", model.AspectSystem,
		freeCheck(),
		model.Options{Syntax: model.SyntaxFree}),
	define.LinuxCheck("time", "System time and timezone", model.AspectSystem,
		[]model.Step{
			{{Label: "timedatectl", Inv: model.NewCommand("timedatectl")}},
			{{Label: "date", Inv: model.Native{Body: native.Date}}},
			{{Label: "date-sh", Inv: model.Sh("date")}},
		},
		model.Options{}),
	define.LinuxCheck("env", "Environment variables (security-relevant)", model.AspectSystem,
		[]model.Step{
			{{Label: "env", Inv: model.Native{Body: native.Env}}},
			{{Label: "env-sh", Inv: model.Sh("env")}},
		},
		model.Options{
			Syntax: model.SyntaxEnv,
			// No filter: a whitelist would hide hijack vectors outside the list
			// (PYTHONPATH/NODE_OPTIONS etc.); a blacklist cannot be exhaustive, so show
			// everything and let the rules color it
			Rules: []model.Matcher{
				model.NewRule("env-ld-library-path", `^LD_LIBRARY_PATH=`, model.Medium, "non-standard library search path"),
				// An empty component (a leading or trailing colon, or `::`) means the
				// current directory just like a bare dot. RE2 has no lookahead, so the
				// test is a disjunction anchored right after `PATH=`: leading colon,
				// any `::`, trailing colon, a leading dot component, a dot component
				// after a colon, an empty value. Anchoring matters: an unanchored
				// colon arm also fires on other variables' empty components
				// (MANPATH=/a::/b, LD_LIBRARY_PATH=/x:/y:), which the message does not
				// describe.
				model.NewRule("env-path-dot", `^PATH=(?::|.*::|.*:$|\.(?::|$)|.*:\.(?::|$)|$)`, model.Medium,
					"PATH has cwd/empty entry (hijackable)"),
				model.NewRule("env-python-path", `^PYTHONPATH=`, model.Medium,
					"PYTHONPATH module path override"),
				define.KeywordRule,
			},
		}),
}
