package startup

import "strings"

// modprobeEdges reads the install/remove commands of a modprobe configuration
// file. `install <module> <command>` runs the command when the module is
// loaded, as root, and the command is a shell line.
func modprobeEdges(file File) []rawEdge {
	var edges []rawEdge
	for index, raw := range strings.Split(file.Body, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words, rest := cutWords(line, 2)
		if len(words) < 2 || rest == "" {
			continue
		}
		if words[0] != "install" && words[0] != "remove" {
			continue
		}
		edges = append(edges, shellSnippetEdges(rest, rawEdge{
			surface: SurfaceModule, phase: BootStaged, subject: Subject{Class: AccountRoot},
			trigger: file.Path, line: index + 1, mechanism: Mechanism(words[0]),
		})...)
	}
	return edges
}
