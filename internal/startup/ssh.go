package startup

import (
	"path/filepath"
	"strings"
	"unicode"
)

// authorizedKeysEdges reads the forced commands of an authorized_keys file:
// an option list carrying command="..." makes the key run that command instead
// of a shell. The option list is split on commas outside quotes, and the
// command is then the shell line it is.
func authorizedKeysEdges(file File) []rawEdge {
	var edges []rawEdge
	as := accountFor(file.Path)
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
				surface: SurfaceSSH, reach: Login, as: as, trigger: file.Path,
				line: index, mechanism: "command=",
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

// sshConfigEdges reads the sshd directives that name a program: the command
// that fetches authorized keys, the principals command for certificates, and
// the forced command applied to every session.
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
				surface: SurfaceSSH, reach: Login, as: "root", trigger: file.Path,
				line: index, mechanism: line[:at],
			})...)
		}
	}
	return edges
}

// pamExecEdges reads a PAM service file for pam_exec.so invocations. The first
// absolute argument after the module is the program PAM runs during
// authentication; the module's own options are skipped.
func pamExecEdges(file File) []rawEdge {
	var edges []rawEdge
	for index, raw := range strings.Split(file.Body, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		for at, field := range fields {
			module := strings.TrimPrefix(field, "-")
			if filepath.Base(module) != "pam_exec.so" {
				continue
			}
			for _, arg := range fields[at+1:] {
				if !filepath.IsAbs(arg) {
					continue
				}
				edges = append(edges, shellEdges(arg, rawEdge{
					surface: SurfacePAM, reach: Login, as: "root", trigger: file.Path,
					line: index, mechanism: "pam_exec",
				})...)
				break
			}
			break
		}
	}
	return edges
}
