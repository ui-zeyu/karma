// system: basic facts: distro and kernel, boot time, clock, environment variables.

package linux

import (
	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/model"
)

const osReleaseScript = "cat /etc/os-release 2>/dev/null || lsb_release -a 2>/dev/null; echo; uname -a"

// SystemChecks covers system information.
var SystemChecks = []*model.Check{
	define.LinuxCheck("os-release", "Distro and kernel", model.AspectSystem,
		[]model.Probe{
			{Label: "cat", Inv: model.Dual{Run: native.OsRelease, Script: osReleaseScript}},
		},
		// os-release is KEY=VALUE, so the env pseudo-lexer is reused directly
		define.CheckOpt{Syntax: model.SyntaxEnv}),
	define.LinuxCheck("uptime", "Hostname and boot time", model.AspectSystem,
		[]model.Probe{
			{Label: "uptime", Inv: model.Dual{Run: native.Uptime, Script: "uptime"}},
			{Label: "proc-uptime", Inv: model.Dual{Run: native.ProcUptime, Script: "cat /proc/uptime"}},
		},
		define.CheckOpt{}),
	define.LinuxCheck("time", "System time and timezone", model.AspectSystem,
		[]model.Probe{
			{Label: "timedatectl", Inv: model.NewCommand("timedatectl")},
			{Label: "date", Inv: model.Dual{Run: native.Date, Script: "date"}},
		},
		define.CheckOpt{}),
	define.LinuxCheck("env", "Environment variables (security-relevant)", model.AspectSystem,
		[]model.Probe{{Label: "env", Inv: model.Dual{Run: native.Env, Script: "env"}}},
		define.CheckOpt{
			Syntax: model.SyntaxEnv,
			// No filter: a whitelist would hide hijack vectors outside the list
			// (PYTHONPATH/NODE_OPTIONS etc.); a blacklist cannot be exhaustive, so show
			// everything and let the rules color it
			Rules: []model.Rule{
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
