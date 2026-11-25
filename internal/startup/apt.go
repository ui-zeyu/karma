package startup

import "strings"

// aptHooks are the apt configuration keys whose value is a shell command apt
// runs during a package operation. They are root's commands: an apt run as a
// user runs them through the setuid/privileged helper as root.
var aptHooks = []string{
	"DPkg::Pre-Invoke",
	"DPkg::Post-Invoke",
	"DPkg::Pre-Install-Pkgs",
	"DPkg::Post-Invoke-Success",
	"APT::Update::Pre-Invoke",
	"APT::Update::Post-Invoke",
	"APT::Update::Post-Invoke-Success",
}

// aptEdges reads the hook commands of an apt configuration file. The format is
// `Key "command";` or a `Key { "command"; "command"; }` block, so the quoted
// strings are the commands whichever spelling carries them.
func aptEdges(file File) []rawEdge {
	var edges []rawEdge
	hook := ""
	for index, raw := range strings.Split(file.Body, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		if hook == "" {
			key, rest, ok := aptHookKey(line)
			if !ok {
				continue
			}
			for _, command := range aptCommands(rest) {
				edges = append(edges, aptCommandEdges(command, file, index, key)...)
			}
			if strings.Contains(rest, "{") && !strings.Contains(rest, "}") {
				hook = key
			}
			continue
		}
		for _, command := range aptCommands(line) {
			edges = append(edges, aptCommandEdges(command, file, index, hook)...)
		}
		if strings.Contains(line, "}") {
			hook = ""
		}
	}
	return edges
}

// aptHookKey reads one line's hook key. A key not in the hook list is not this
// parser's business.
func aptHookKey(line string) (key, rest string, ok bool) {
	for _, candidate := range aptHooks {
		if !strings.HasPrefix(line, candidate) {
			continue
		}
		after := line[len(candidate):]
		if after != "" && after[0] != ' ' && after[0] != '\t' && after[0] != '{' && after[0] != '"' {
			continue
		}
		return candidate, strings.TrimSpace(after), true
	}
	return "", "", false
}

func aptCommandEdges(command string, file File, index int, key string) []rawEdge {
	if strings.TrimSpace(command) == "" {
		return nil
	}
	return shellEdges(command, rawEdge{
		surface: SurfaceApt, reach: Scheduled, as: "root",
		trigger: file.Path, line: index, mechanism: key,
	})
}

// aptCommands reads every double-quoted string on a line, with backslash
// escapes unwound.
func aptCommands(line string) []string {
	var commands []string
	for at := 0; at < len(line); at++ {
		if line[at] != '"' {
			continue
		}
		var current strings.Builder
		closed := false
		for index := at + 1; index < len(line); index++ {
			switch line[index] {
			case '\\':
				if index+1 < len(line) {
					index++
					current.WriteByte(line[index])
				}
			case '"':
				closed = true
				at = index
			default:
				current.WriteByte(line[index])
			}
			if closed {
				break
			}
		}
		if closed {
			commands = append(commands, current.String())
		}
	}
	return commands
}

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
		edges = append(edges, shellEdges(rest, rawEdge{
			surface: SurfaceModule, reach: BootStaged, as: "root",
			trigger: file.Path, line: index, mechanism: words[0],
		})...)
	}
	return edges
}
