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
// shape) / waiting, and SysV's [ + ]/[ - ]. The systemd test is anchored on the
// ACTIVE column — UNIT LOAD ACTIVE — so a state word inside DESCRIPTION ("GRUB
// failed boot detection") cannot keep an inactive row; systemctl marks a failed
// unit with a leading ●, which is one token of its own before UNIT. Header rows
// are kept too -- table highlighting anchors column starts on the uppercase
// header and leaves the last column plain, so dropping the header degrades the
// whole table to word cycling.
const unitStateKeep = `^\s*UNIT\b|^\s*(?:●\s+)?\S+\s+\S+\s+(?:active|failed|activating|waiting)\s|^\s*\[\s*[?+-]\s*\]`

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
			Rules: []model.Matcher{
				model.NewRule("unit-crashloop", `\bauto-restart\b`, model.Medium,
					"service crash loop (dwell sign)"),
			},
		}),
	define.LinuxCheck("timers", "systemd timers", model.AspectService,
		[]model.Step{{{Label: "systemctl", Inv: model.NewCommand("systemctl", "list-timers", "--all")}}},
		// list-timers' date cells span several words, which the generic table
		// styler would color word by word; the timers lexer paints each whole
		// cell.
		define.CheckOpt{Syntax: model.SyntaxTimers}),
}
