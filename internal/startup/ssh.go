package startup

import (
	"strings"
	"unicode"
)

// authorizedKeysEdges reads the forced commands of an authorized_keys file:
// an option list carrying command="..." makes the key run that command instead
// of a shell. The option list is split on commas outside quotes, and the
// command is then the shell line it is.
func authorizedKeysEdges(file File) []rawEdge {
	var edges []rawEdge
	subject := accountFor(file.Path)
	for index, raw := range strings.Split(file.Body, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		options, _ := cutKeyOptions(line)
		if !strings.Contains(options, "command=") {
			continue
		}
		for _, option := range udevFields(options) {
			key, value, ok := udevKeyValue(option)
			if !ok || key != "command" {
				continue
			}
			value = unquote(value)
			if value == "" {
				continue
			}
			edges = append(edges, shellEdges(value, rawEdge{
				surface: SurfaceSSH, phase: Login, subject: subject, trigger: file.Path,
				line: index + 1, mechanism: "command=",
			})...)
		}
	}
	return edges
}

// cutKeyOptions cuts the option list from the key that follows it, keeping a
// quoted blank inside an option value.
func cutKeyOptions(line string) (options, rest string) {
	quoted := false
	escaped := false
	for index := 0; index < len(line); index++ {
		switch c := line[index]; {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case !quoted && (c == ' ' || c == '\t'):
			return line[:index], strings.TrimLeft(line[index:], " \t")
		}
	}
	return line, ""
}

// sshConfigEdges reads the ssh daemon and client directives that name a
// program: the commands that fetch authorized keys or principals, the forced
// command applied to every session, and the client's ProxyCommand and
// LocalCommand.
func sshConfigEdges(file File) []rawEdge {
	var edges []rawEdge
	for index, raw := range strings.Split(file.Body, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		at := strings.IndexFunc(line, unicode.IsSpace)
		if at < 0 {
			continue
		}
		key := strings.ToLower(line[:at])
		value := strings.TrimSpace(line[at:])
		switch key {
		case "authorizedkeyscommand", "authorizedprincipalscommand", "forcecommand":
			if value == "" || value == "none" {
				continue
			}
			edges = append(edges, shellEdges(value, rawEdge{
				surface: SurfaceSSH, phase: Login, subject: Subject{Class: AccountRoot}, trigger: file.Path,
				line: index + 1, mechanism: Mechanism(line[:at]),
			})...)
		case "proxycommand", "localcommand":
			if value == "" || value == "none" {
				continue
			}
			edges = append(edges, shellEdges(value, rawEdge{
				surface: SurfaceSSH, phase: Session, subject: accountFor(file.Path), trigger: file.Path,
				line: index + 1, mechanism: Mechanism(line[:at]),
			})...)
		}
	}
	return edges
}
