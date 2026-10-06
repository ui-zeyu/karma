// service: systemd services and timers, with a SysV fallback.
//
// From the full --all listing only rows whose ACTIVE column is active/failed are
// kept: stopped-but-enabled services are covered by persistence.enabled-units.

package linux

import (
	"karma/internal/define"
	"karma/internal/model"
)

// unitStateKeep: the "worth looking at" rows in both probe formats: systemd's
// active/failed/activating (including auto-restart crash loops, a common malware
// shape) / waiting, and SysV's [ + ]/[ - ]. Header rows are kept too -- table
// highlighting anchors column starts on the uppercase header and leaves the last
// column plain, so dropping the header degrades the whole table to word cycling.
const unitStateKeep = `^\s*UNIT\b|\s(?:active|failed|activating|waiting)\s|^\s*\[\s*[?+-]\s*\]`

// ServiceChecks covers services.
var ServiceChecks = []*model.Check{
	define.LinuxCheck("services", "Running services", model.AspectService,
		[]model.Step{
			{{Label: "systemctl", Inv: model.NewCommand("systemctl", "list-units", "--type=service", "--all")}},
			{{Label: "service", Inv: model.NewCommand("service", "--status-all")}},
		},
		define.CheckOpt{
			// The systemd probe's header legend row does not match the keep pattern
			// and is hidden by count
			Filters: []model.LineFilter{
				model.NewFilter("unit-state", unitStateKeep, model.FilterKeep),
			},
			Syntax: model.SyntaxUnits,
			Rules: []model.Rule{
				model.NewRule("unit-crashloop", `\bauto-restart\b`, model.Medium,
					"service crash loop (dwell sign)"),
			},
		}),
	define.LinuxCheck("timers", "systemd timers", model.AspectService,
		[]model.Step{{{Label: "systemctl", Inv: model.NewCommand("systemctl", "list-timers", "--all")}}},
		define.CheckOpt{Syntax: model.SyntaxTable}),
}
