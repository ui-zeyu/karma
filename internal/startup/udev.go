package startup

import "strings"

// udevEdges reads the rule layers an administrator writes. A rule's RUN,
// PROGRAM and IMPORT{program} values are programs udev runs as root when the
// device event matches; the value is a shell command only when it names one.
// The rule file is the trigger and the rule's line is the evidence.
func udevEdges(file File) []rawEdge {
	var edges []rawEdge
	for index, raw := range strings.Split(file.Body, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, field := range udevFields(line) {
			key, value, ok := udevKeyValue(field)
			if !ok || !udevRunsProgram(key) || value == "" {
				continue
			}
			value = unquote(value)
			if value == "" {
				continue
			}
			edges = append(edges, shellSnippetEdges(value, rawEdge{
				surface:   SurfaceUdev,
				phase:     Device,
				subject:   Subject{Class: AccountRoot},
				trigger:   file.Path,
				line:      index + 1,
				mechanism: Mechanism(key),
			})...)
		}
	}
	return edges
}

// udevFields splits one rule at its commas, keeping a comma inside a quoted
// value. The quotes stay so the value reader can tell a quoted command from
// two words.
func udevFields(line string) []string {
	var (
		fields  []string
		current strings.Builder
		quoted  bool
		escaped bool
	)
	for index := 0; index < len(line); index++ {
		c := line[index]
		switch {
		case escaped:
			current.WriteByte(c)
			escaped = false
		case c == '\\':
			current.WriteByte(c)
			escaped = true
		case c == '"':
			quoted = !quoted
			current.WriteByte(c)
		case c == ',' && !quoted:
			if strings.TrimSpace(current.String()) != "" {
				fields = append(fields, current.String())
			}
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	if strings.TrimSpace(current.String()) != "" {
		fields = append(fields, current.String())
	}
	return fields
}

// udevKeyValue splits one `KEY==value` field. The operator is the first '=',
// and a trailing +, : or ! belongs to the operator, not the key.
func udevKeyValue(field string) (key, value string, ok bool) {
	at := strings.IndexByte(field, '=')
	if at < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(field[:at])
	key = strings.TrimRight(key, "+:!")
	value = strings.TrimSpace(field[at+1:])
	if strings.HasPrefix(value, "=") {
		value = strings.TrimSpace(value[1:])
	}
	return key, value, key != ""
}

// udevRunsProgram reports whether the key names a program udev executes.
// RUN{builtin} runs a udev builtin, which is not a file edge; IMPORT{builtin}
// is the same.
func udevRunsProgram(key string) bool {
	switch key {
	case "RUN", "PROGRAM", "IMPORT{program}":
		return true
	}
	if strings.HasPrefix(key, "RUN{") {
		return key != "RUN{builtin}"
	}
	return false
}
