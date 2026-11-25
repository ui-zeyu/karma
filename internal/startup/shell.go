package startup

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// shellEdges reads a POSIX shell file's startup edges. The parser is the shell
// language's own: an assignment, a source and an exec are recognized as the
// syntax it is, whatever the line is indented like and whichever branch of an
// if it sits in. A file that is not a shell script parses to nothing, which is
// the quiet answer for a completion helper or a locale fix.
func shellEdges(src string, base rawEdge) []rawEdge {
	file, err := syntax.NewParser().Parse(strings.NewReader(src), base.trigger)
	if err != nil {
		return nil
	}
	var edges []rawEdge
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				// A bare assignment sequence sets the shell's own variables.
				// The transient `FOO=bar cmd` form is a CallExpr with Args and
				// is not a variable a later script sees, so it is not read.
				edges = append(edges, assignmentEdges(base, node.Assigns)...)
				return true
			}
			edges = append(edges, commandEdges(src, base, node.Args)...)
		case *syntax.DeclClause:
			// export, declare, typeset and local all carry assignments whose
			// names and values are the same syntax.
			edges = append(edges, assignmentEdges(base, node.Args)...)
		}
		return true
	})
	return edges
}

// commandEdges reads one simple command: a source, an exec, an eval of a
// literal script, or a program the shell named by path.
func commandEdges(src string, base rawEdge, args []*syntax.Word) []rawEdge {
	first, literal := wordLit(args[0])
	if !literal {
		word := wordText(src, args[0])
		if looksLikePath(word) {
			return []rawEdge{edgeFor(base, args[0], word, Exec, false, true)}
		}
		return nil
	}
	switch first {
	case "source", ".":
		return sourceEdges(src, base, args[1:])
	case "exec":
		return literalCommandEdges(src, base, args[1:], "exec")
	case "eval":
		if len(args) < 2 {
			return nil
		}
		if code, ok := wordLit(args[1]); ok {
			return shellEdges(code, base)
		}
		// eval of a command's output is code the file does not hold; there is
		// no literal target to place and nothing a static read can name.
		return nil
	case "command", "builtin":
		return literalCommandEdges(src, base, args[1:], first)
	}
	return literalCommandEdges(src, base, args, "exec")
}

// sourceEdges reads `source path` and `. path`. A literal absolute path is the
// edge; a variable or relative path is stated as dynamic, because the static
// read cannot place it and a later session is where it resolves.
func sourceEdges(src string, base rawEdge, args []*syntax.Word) []rawEdge {
	for _, arg := range args {
		if literal, ok := wordLit(arg); ok && strings.HasPrefix(literal, "-") {
			continue
		}
		target, ok := wordLit(arg)
		if !ok {
			return []rawEdge{edgeFor(base, arg, wordText(src, arg), Source, false, true)}
		}
		if !filepath.IsAbs(target) {
			return []rawEdge{edgeFor(base, arg, target, Source, false, true)}
		}
		return []rawEdge{edgeFor(base, arg, target, Source, false, false)}
	}
	return nil
}

// literalCommandEdges reads the words after a command prefix (exec, command,
// builtin). Every word up to the program is needed; a non-literal word before
// the target makes the target dynamic rather than guessed.
func literalCommandEdges(src string, base rawEdge, args []*syntax.Word, mechanism string) []rawEdge {
	if mechanism != "" && base.mechanism == "" {
		// A surface that named the mechanism (a unit's ExecStart, an
		// authorized key's command=) keeps its own word; a bare profile line
		// is an exec.
		base.mechanism = mechanism
	}
	words := make([]string, 0, len(args))
	for _, arg := range args {
		word, ok := wordLit(arg)
		if !ok {
			if len(words) == 0 {
				word = wordText(src, arg)
				if !looksLikePath(word) {
					return nil
				}
				return []rawEdge{edgeFor(base, arg, word, Exec, false, true)}
			}
			target, kind, viaInterpreter, dynamic := literalTarget(words)
			switch {
			case dynamic:
				return []rawEdge{edgeFor(base, arg, wordText(src, arg), Exec, false, true)}
			case target != "":
				return []rawEdge{edgeFor(base, arg, target, kind, viaInterpreter, false)}
			case isWrapper(words[0]) || IsInterpreter(words[0]):
				// The wrapper or interpreter was still looking for its script
				// when the word stopped being literal.
				return []rawEdge{edgeFor(base, arg, wordText(src, arg), Exec, false, true)}
			}
			return nil
		}
		words = append(words, word)
	}
	target, kind, viaInterpreter, dynamic := literalTarget(words)
	if target == "" && !dynamic {
		return nil
	}
	return []rawEdge{edgeFor(base, args[0], target, kind, viaInterpreter, dynamic)}
}

// literalTarget is the shared reading of a command word list, for a shell line
// and for an ExecStart. The shell spelling allows a bare command name to be a
// PATH lookup; a unit's ExecStart does not.
func literalTarget(words []string) (string, Kind, bool, bool) {
	if len(words) == 0 {
		return "", "", false, false
	}
	target := commandTargetFor(words, true)
	if target.kind == "" {
		target.kind = Exec
	}
	return target.target, target.kind, target.viaInterpreter, target.dynamic
}

// assignmentEdges reads the assignments whose value is a path. The loader
// variables are the loader's own edge; any other variable that holds one
// existing file's path is an environment edge, which is how a login file hands
// a hidden script to a later session without running it.
func assignmentEdges(base rawEdge, assigns []*syntax.Assign) []rawEdge {
	var edges []rawEdge
	for _, assign := range assigns {
		if assign.Name == nil || assign.Value == nil {
			continue
		}
		name := assign.Name.Value
		value, ok := wordLit(assign.Value)
		if !ok {
			continue
		}
		mechanism := base
		mechanism.mechanism = "export " + name
		if name == "LD_PRELOAD" || name == "LD_AUDIT" {
			for _, path := range splitPaths(value) {
				edges = append(edges, edgeFor(mechanism, assign.Value, path, Preload, false, !filepath.IsAbs(path)))
			}
			continue
		}
		if !filepath.IsAbs(value) || strings.ContainsAny(value, " \t:") {
			continue
		}
		edges = append(edges, edgeFor(mechanism, assign.Value, value, Env, false, false))
	}
	return edges
}

// environmentEdges reads /etc/environment, whose format is one KEY=VALUE per
// line read by pam_env rather than by a shell.
func environmentEdges(body string, base rawEdge) []rawEdge {
	var edges []rawEdge
	for index, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		value = unquote(strings.TrimSpace(value))
		at := base.line + index + 1
		if name == "LD_PRELOAD" || name == "LD_AUDIT" {
			for _, path := range splitPaths(value) {
				edges = append(edges, rawEdge{
					surface: base.surface, reach: base.reach, as: base.as,
					trigger: base.trigger, line: at,
					mechanism: name, target: path, kind: Preload, dynamic: !filepath.IsAbs(path),
				})
			}
			continue
		}
		if !filepath.IsAbs(value) || strings.ContainsAny(value, " \t:") {
			continue
		}
		edges = append(edges, rawEdge{
			surface: base.surface, reach: base.reach, as: base.as,
			trigger: base.trigger, line: at,
			mechanism: name, target: value, kind: Env,
		})
	}
	return edges
}

// edgeFor builds one edge at the node that named the target.
func edgeFor(base rawEdge, node syntax.Node, target string, kind Kind, viaInterpreter, dynamic bool) rawEdge {
	line := base.line
	if node != nil {
		// base.line is the offset of the snippet a nested command was read
		// from (a crontab command, a udev value), so the report names the file's
		// line and not the snippet's.
		line = base.line + int(node.Pos().Line())
	}
	mechanism := base.mechanism
	if mechanism == "" {
		mechanism = string(kind)
	}
	return rawEdge{
		surface:        base.surface,
		reach:          base.reach,
		as:             base.as,
		trigger:        base.trigger,
		line:           line,
		mechanism:      mechanism,
		target:         target,
		kind:           kind,
		viaInterpreter: viaInterpreter,
		dynamic:        dynamic,
	}
}

// wordLit is a word with no expansion: an unquoted literal, a single-quoted
// one, or a double-quoted one holding one literal part.
func wordLit(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false
	}
	switch part := word.Parts[0].(type) {
	case *syntax.Lit:
		return part.Value, true
	case *syntax.SglQuoted:
		if part.Dollar {
			return "", false
		}
		return part.Value, true
	case *syntax.DblQuoted:
		if len(part.Parts) == 0 {
			return "", true
		}
		if len(part.Parts) == 1 {
			if literal, ok := part.Parts[0].(*syntax.Lit); ok {
				return literal.Value, true
			}
		}
	}
	return "", false
}

// wordText is a word's source spelling, for the dynamic rows where the target
// is exactly what the trigger wrote.
func wordText(src string, word *syntax.Word) string {
	if word == nil {
		return ""
	}
	start, end := int(word.Pos().Offset()), int(word.End().Offset())
	if start < 0 || end <= start || end > len(src) {
		return ""
	}
	return strings.TrimSpace(src[start:end])
}
