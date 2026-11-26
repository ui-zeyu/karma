package startup

import "strings"

// supervisorEdges reads the process supervisors and the container entrypoint.
// A supervisor INI states one command per program/eventlistener section, run as
// root unless the section names a user. An s6 run script or an entrypoint
// script is a shell file, read as the shell it is.
func supervisorEdges(file File) []rawEdge {
	if file.Dialect == ShellDialect {
		return shellEdges(file.Body, rawEdge{
			surface: SurfaceSupervisor, phase: BootStaged, subject: Subject{Class: AccountRoot}, trigger: file.Path,
		})
	}
	directives := parseUnit(file.Body)
	users := map[string]string{}
	for _, d := range directives {
		if supervisorSection(d.section) && d.key == "user" && d.value != "" {
			users[d.section] = unquote(d.value)
		}
	}
	var edges []rawEdge
	for _, d := range directives {
		if !supervisorSection(d.section) || d.key != "command" || d.value == "" {
			continue
		}
		subject := Subject{Class: AccountRoot}
		if user, ok := users[d.section]; ok {
			subject = Account(user)
		}
		edges = append(edges, shellEdges(d.value, rawEdge{
			surface: SurfaceSupervisor, phase: BootStaged, subject: subject,
			trigger: file.Path, line: d.line, mechanism: "command",
		})...)
	}
	return edges
}

// supervisorSection names the INI sections that carry a command. Supervisor's
// include and group sections do not.
func supervisorSection(section string) bool {
	return strings.HasPrefix(section, "program:") || strings.HasPrefix(section, "eventlistener:")
}

// desktopEdges reads an XDG autostart entry. Exec is a command line and
// TryExec is the program the session checks before offering the entry; the
// account is the one whose autostart directory holds the file.
func desktopEdges(file File) []rawEdge {
	subject := accountFor(file.Path)
	var edges []rawEdge
	for _, d := range parseUnit(file.Body) {
		if d.section != "Desktop Entry" {
			continue
		}
		switch d.key {
		case "Exec", "TryExec":
			if d.value == "" {
				continue
			}
			edges = append(edges, shellEdges(d.value, rawEdge{
				surface: SurfaceXdg, phase: Session, subject: subject,
				trigger: file.Path, line: d.line, mechanism: Mechanism(d.key),
			})...)
		}
	}
	return edges
}
