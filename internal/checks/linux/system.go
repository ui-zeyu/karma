// system: basic facts: distro and kernel, boot time, clock, environment variables.
package linux

import (
	"karma/internal/define"
	"karma/internal/model"
)

const osReleaseScript = "cat /etc/os-release 2>/dev/null || lsb_release -a 2>/dev/null; echo; uname -a"

// SystemChecks covers system information.
var SystemChecks = []*model.Check{
	define.LinuxCheck("os-release", "Distro and kernel", model.AspectSystem,
		[]model.Probe{{Label: "cat", Inv: model.Shell{Script: osReleaseScript}}},
		// os-release is KEY=VALUE, so the env pseudo-lexer is reused directly
		define.CheckOpt{Syntax: "env"}),
	define.LinuxCheck("uptime", "Hostname and boot time", model.AspectSystem,
		[]model.Probe{
			{Label: "uptime", Inv: model.NewCommand("uptime")},
			{Label: "proc-uptime", Inv: model.Shell{Script: "cat /proc/uptime"}},
		},
		define.CheckOpt{}),
	define.LinuxCheck("time", "System time and timezone", model.AspectSystem,
		[]model.Probe{
			{Label: "timedatectl", Inv: model.NewCommand("timedatectl")},
			{Label: "date", Inv: model.NewCommand("date")},
		},
		define.CheckOpt{}),
	define.LinuxCheck("env", "Environment variables (security-relevant)", model.AspectSystem,
		[]model.Probe{{Label: "env", Inv: model.NewCommand("env")}},
		define.CheckOpt{
			Syntax: "env",
			// No filter: a whitelist would hide hijack vectors outside the list
			// (PYTHONPATH/NODE_OPTIONS etc.); a blacklist cannot be exhaustive, so show
			// everything and let the rules color it
			Rules: []model.Rule{
				model.NewRule("env-ld-preload", `^LD_PRELOAD=`, model.High, "environment-level dynamic library preload"),
				model.NewRule("env-ld-library-path", `^LD_LIBRARY_PATH=`, model.Medium, "non-standard library search path"),
				// An empty component (::, leading/trailing colon, trailing PATH colon) means
				// the current directory just like a bare dot; RE2 has no lookahead, so `(?=$|:)`
				// is rewritten as an equivalent disjunction consuming the delimiter, and the
				// trailing empty component is caught by the `$` arm.
				model.NewRule("env-path-dot", `(^PATH=|:)(?:\.($|:)|:$|:|$)`, model.Medium,
					"PATH contains the current directory or an empty component (hijackable via a same-named program)"),
				model.NewRule("env-python-path", `^PYTHONPATH=`, model.Medium,
					"Python module search path set (watch for malicious module injection)"),
				define.KeywordRule,
			},
		}),
}
