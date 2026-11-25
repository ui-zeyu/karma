package startup

import (
	"path/filepath"
	"sort"
	"strings"
)

// directive is one key in a unit file, with the line it was read from. A
// continued line reports the line it started on.
type directive struct {
	section string
	key     string
	value   string
	line    int
}

// parseUnit reads a systemd unit or drop-in. The syntax is the small one the
// format defines: a section header, `Key=Value`, comments led by # or ;, and a
// trailing backslash joining the next line. A line the format does not define
// is ignored rather than guessed at.
func parseUnit(body string) []directive {
	var directives []directive
	lines := strings.Split(body, "\n")
	section := ""
	for index := 0; index < len(lines); index++ {
		line := strings.TrimRight(lines[index], "\r")
		start := index + 1
		for strings.HasSuffix(line, "\\") && index+1 < len(lines) {
			line = strings.TrimSuffix(line, "\\")
			index++
			line += strings.TrimRight(lines[index], "\r")
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == ';' {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = trimmed[1 : len(trimmed)-1]
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		directives = append(directives, directive{
			section: section,
			key:     strings.TrimSpace(key),
			value:   strings.TrimSpace(value),
			line:    start,
		})
	}
	return directives
}

// valueRef is one directive's value and where it came from. A list key's
// values keep the file that supplied each one, so the edge names the trigger
// an analyst has to edit, not the unit the drop-in overrides.
type valueRef struct {
	file  string
	line  int
	value string
}

// unitState is one unit after its files and drop-ins are applied in precedence
// order. Only the keys that carry an edge are kept.
type unitState struct {
	as       string
	userSet  bool
	dynamic  bool
	exec     map[string][]valueRef
	env      []valueRef
	envFiles []valueRef
}

func newUnitState() *unitState {
	return &unitState{as: "root", exec: map[string][]valueRef{}}
}

// execOrder is the order the service keys are stated in. ExecStart is the
// program; the others run around it, and all of them name a file.
var execOrder = []string{"ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"}

func (u *unitState) apply(file string, d directive) {
	if d.section != "Service" {
		return
	}
	switch d.key {
	case "ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost":
		// An empty assignment clears the list the earlier files built.
		if d.value == "" {
			delete(u.exec, d.key)
			return
		}
		u.exec[d.key] = append(u.exec[d.key], valueRef{file: file, line: d.line, value: d.value})
	case "Environment":
		if d.value == "" {
			u.env = nil
			return
		}
		u.env = append(u.env, valueRef{file: file, line: d.line, value: d.value})
	case "EnvironmentFile":
		if d.value == "" {
			u.envFiles = nil
			return
		}
		u.envFiles = append(u.envFiles, valueRef{file: file, line: d.line, value: d.value})
	case "User":
		if d.value == "" {
			// The manager's default: root for the system manager, the unit's
			// owner for a user manager.
			u.as = "root"
			u.userSet = false
			return
		}
		u.as = unquote(d.value)
		u.userSet = true
	case "DynamicUser":
		u.dynamic = isYes(d.value)
	}
}

// applyFiles folds one unit's files. A unit file in a higher-precedence
// directory replaces the lower one whole — that is what shadowing means — so
// only the highest-precedence unit file is read; every directory's drop-ins
// still apply, lowest first, because a drop-in is additive by definition.
func applyFiles(files []File) *unitState {
	var base *File
	var dropIns []File
	for index := range files {
		if files[index].DropIn {
			dropIns = append(dropIns, files[index])
			continue
		}
		if base == nil || unitPrecedence(files[index].Path) >= unitPrecedence(base.Path) {
			base = &files[index]
		}
	}
	sort.SliceStable(dropIns, func(i, j int) bool {
		left, right := unitPrecedence(dropIns[i].Path), unitPrecedence(dropIns[j].Path)
		if left != right {
			return left < right
		}
		return dropIns[i].Path < dropIns[j].Path
	})

	state := newUnitState()
	if base != nil {
		for _, d := range parseUnit(base.Body) {
			state.apply(base.Path, d)
		}
	}
	for _, file := range dropIns {
		for _, d := range parseUnit(file.Body) {
			state.apply(file.Path, d)
		}
	}
	return state
}

// unitPrecedence is systemd's own directory order, lowest first. Only the
// administrator layers are collected; the vendor tree is the baseline, never an
// edge of its own.
func unitPrecedence(path string) int {
	switch {
	case strings.HasPrefix(path, "/etc/systemd/"):
		return 3
	case strings.HasPrefix(path, "/run/systemd/"):
		return 2
	case strings.HasPrefix(path, "/usr/local/lib/systemd/"):
		return 1
	}
	return 0
}

// commandTarget is what one ExecStart (or a shell command) says to run.
type commandTarget struct {
	target         string
	kind           Kind
	viaInterpreter bool
	dynamic        bool
}

// execTarget reads one ExecStart value. The prefix characters systemd allows
// (-@+!:) are dropped, the finite wrapper vocabulary (env, nohup, setsid,
// timeout, nice, ionice, sudo) is unwrapped, and an interpreter holding a
// script names the script rather than the interpreter. A target that is not a
// literal path is stated as dynamic; the static read cannot resolve it and the
// runtime view is where it belongs.
func execTarget(value string) commandTarget {
	words := splitWords(strings.TrimLeft(value, "-@+!:"))
	return commandTargetFor(words, false)
}

// commandTargetFor reads a command word list. fromShell is true when the words
// came from a shell line rather than a unit key, which is what lets a bare
// command name be a PATH lookup (no edge) instead of a missing path.
func commandTargetFor(words []string, fromShell bool) commandTarget {
	for len(words) > 0 {
		switch filepath.Base(words[0]) {
		case "env":
			words = words[1:]
		envOptions:
			for len(words) > 0 {
				switch {
				case words[0] == "--":
					words = words[1:]
					break envOptions
				case words[0] == "-u" || words[0] == "--unset":
					if len(words) > 1 {
						words = words[2:]
					} else {
						words = nil
					}
				case strings.HasPrefix(words[0], "--unset="):
					words = words[1:]
				case strings.HasPrefix(words[0], "-"):
					words = words[1:]
				case !strings.HasPrefix(words[0], "/") && strings.Contains(words[0], "="):
					words = words[1:]
				default:
					break envOptions
				}
			}
		case "nohup", "setsid", "unbuffer":
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				words = words[1:]
			}
		case "timeout":
			words = words[1:]
		timeoutOptions:
			for len(words) > 0 {
				switch {
				case (words[0] == "-s" || words[0] == "--signal" || words[0] == "-k" || words[0] == "--kill-after") && len(words) > 1:
					words = words[2:]
				case strings.HasPrefix(words[0], "-"):
					words = words[1:]
				default:
					break timeoutOptions
				}
			}
			if len(words) == 0 {
				return commandTarget{dynamic: true, target: "(timeout)"}
			}
			words = words[1:] // the duration
		case "nice":
			words = words[1:]
			for len(words) > 0 {
				if words[0] == "-n" && len(words) > 1 {
					words = words[2:]
					continue
				}
				if strings.HasPrefix(words[0], "-") {
					words = words[1:]
					continue
				}
				break
			}
		case "ionice":
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				words = words[1:]
			}
		case "sudo":
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				if (words[0] == "-u" || words[0] == "-g") && len(words) > 1 {
					words = words[2:]
					continue
				}
				words = words[1:]
			}
		default:
			goto program
		}
	}
program:
	if len(words) == 0 {
		return commandTarget{}
	}
	program := words[0]
	if IsInterpreter(program) {
		return interpreterTarget(program, words[1:])
	}
	if !filepath.IsAbs(program) {
		if fromShell && !looksLikePath(program) {
			// A bare name is the shell's PATH lookup, not a file edge. A
			// relative path is an edge the static read cannot place.
			return commandTarget{}
		}
		return commandTarget{target: program, dynamic: true}
	}
	return commandTarget{target: program, kind: Exec}
}

// interpreterTarget reads the arguments of an interpreter. -c holds inline
// code, whose first literal local target is the script it runs; a -m module and
// a bare argument are not files. A non-literal script argument is dynamic.
func interpreterTarget(program string, args []string) commandTarget {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "-c":
			if index+1 >= len(args) {
				return commandTarget{dynamic: true, target: "(inline code)"}
			}
			target, kind, ok := inlineTarget(args[index+1])
			if !ok {
				return commandTarget{dynamic: true, target: "(inline code)"}
			}
			return commandTarget{target: target, kind: kind, viaInterpreter: true}
		case arg == "-m":
			return commandTarget{}
		case strings.HasPrefix(arg, "-"):
			continue
		case filepath.IsAbs(arg):
			return commandTarget{target: arg, kind: Exec, viaInterpreter: true}
		default:
			return commandTarget{dynamic: true, target: arg}
		}
	}
	return commandTarget{dynamic: true, target: "(inline code)"}
}

// inlineTarget reads the first local target of a shell -c string: a source, an
// exec, or a command whose program is a literal path.
func inlineTarget(code string) (string, Kind, bool) {
	for _, edge := range shellEdges(code, rawEdge{}) {
		if edge.dynamic || edge.target == "" {
			continue
		}
		return edge.target, edge.kind, true
	}
	return "", "", false
}

// environmentPreloads reads one Environment= value and states the loader paths
// it hands to the service. systemd splits the value on whitespace with its own
// quoting; LD_PRELOAD and LD_AUDIT take a list of libraries.
func environmentPreloads(value string) (varName string, paths []string) {
	for _, word := range splitWords(value) {
		name, val, ok := strings.Cut(word, "=")
		if !ok || (name != "LD_PRELOAD" && name != "LD_AUDIT") {
			continue
		}
		paths = append(paths, splitPaths(val)...)
		varName = name
	}
	return varName, paths
}

func splitPaths(value string) []string {
	var paths []string
	for _, field := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == ':'
	}) {
		if filepath.IsAbs(field) {
			paths = append(paths, field)
		}
	}
	return paths
}

// splitWords is systemd's word splitting: whitespace separates, single and
// double quotes group, and a backslash escapes the next byte. It is also the
// reading EnvironmentFile and Environment= need.
func splitWords(value string) []string {
	var (
		words   []string
		current strings.Builder
		inWord  bool
		quote   byte
	)
	for index := 0; index < len(value); index++ {
		c := value[index]
		if quote != 0 {
			switch {
			case c == quote:
				quote = 0
			case c == '\\' && quote == '"' && index+1 < len(value):
				index++
				current.WriteByte(unescape(value[index]))
			default:
				current.WriteByte(c)
			}
			continue
		}
		switch c {
		case ' ', '\t', '\n':
			if inWord {
				words = append(words, current.String())
				current.Reset()
				inWord = false
			}
		case '\'', '"':
			quote = c
			inWord = true
		case '\\':
			if index+1 < len(value) {
				index++
				current.WriteByte(unescape(value[index]))
				inWord = true
			}
		default:
			current.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, current.String())
	}
	return words
}

func unescape(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 't':
		return '\t'
	case 'r':
		return '\r'
	case 's':
		return ' '
	}
	return c
}

func unquote(value string) string {
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		return value[1 : len(value)-1]
	}
	return value
}

func isYes(value string) bool {
	switch strings.ToLower(unquote(value)) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}

// interpreterNames are the programs whose first script argument names a file
// the interpreter reads. The version suffix is cut before the lookup, so
// python3.12 and python3 are the same program.
var interpreterNames = []string{
	"bash", "sh", "dash", "zsh", "ksh", "fish",
	"python", "perl", "ruby", "node", "php", "lua",
}

// ScriptArg is the first non-option argument after an interpreter. A -c, -e,
// -r or -m argument means the code or module is inline, so there is no script
// path; a relative path is resolved by the caller against the process's cwd.
func ScriptArg(cmdline string) string {
	args := strings.Fields(cmdline)
	for _, arg := range args[1:] {
		switch arg {
		case "-c", "-e", "-r", "-m":
			return ""
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

// IsInterpreter reports whether path names one of the shell or scripting
// interpreters whose first non-option argument is a script. The static edge
// reader and the live watcher share this list, so a new interpreter cannot be
// known to one and unknown to the other.
func IsInterpreter(path string) bool {
	base := filepath.Base(path)
	base = strings.TrimRight(base, "0123456789.")
	for _, name := range interpreterNames {
		if base == name {
			return true
		}
	}
	return false
}

// isWrapper names the launch wrappers whose first non-option argument is the
// program that actually runs.
func isWrapper(program string) bool {
	switch filepath.Base(program) {
	case "env", "nohup", "setsid", "unbuffer", "timeout", "nice", "ionice", "sudo":
		return true
	}
	return false
}

// looksLikePath reports whether a shell word that is not absolute names a path
// rather than a command: a relative path, a home-relative one, or an expansion
// that carries a separator. A bare $variable is a command the shell looks up in
// PATH, not a file edge.
func looksLikePath(word string) bool {
	return strings.Contains(word, "/")
}
