package startup

import (
	"path/filepath"
	"strings"
)

// cronEdges reads a crontab-format file: /etc/crontab, /etc/cron.d/*,
// /etc/anacrontab and the user spool. The schedule is not a target; the
// command after it is a shell line, and the environment assignments above it
// are the same loader/path edges a login file carries.
func cronEdges(file File) []rawEdge {
	var edges []rawEdge
	system := isSystemCrontab(file.Path)
	anacron := file.Path == "/etc/anacrontab"
	defaultSubject := cronFileSubject(file.Path)

	for index, raw := range strings.Split(file.Body, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if name, _, ok := strings.Cut(line, "="); ok && !strings.ContainsAny(name, " \t") {
			edges = append(edges, environmentEdges(line, rawEdge{
				surface: SurfaceCron, phase: Scheduled, subject: defaultSubject,
				trigger: file.Path, line: index,
			})...)
			continue
		}

		phase := Scheduled
		subject := defaultSubject
		var command string
		switch {
		case anacron:
			// period delay job-identifier command
			words, rest := cutWords(line, 3)
			if len(words) < 3 || rest == "" {
				continue
			}
			command = rest
		case strings.HasPrefix(line, "@"):
			// @event [user] command
			words, rest := cutWords(line, 1)
			if len(words) == 0 || rest == "" {
				continue
			}
			if words[0] == "@reboot" {
				phase = BootStaged
			}
			if system {
				user, tail := cutWords(rest, 1)
				if len(user) == 0 || tail == "" {
					continue
				}
				subject = Account(user[0])
				command = tail
			} else {
				command = rest
			}
		default:
			// minute hour day month weekday [user] command
			words, rest := cutWords(line, 5)
			if len(words) < 5 || rest == "" {
				continue
			}
			if system {
				user, tail := cutWords(rest, 1)
				if len(user) == 0 || tail == "" {
					continue
				}
				subject = Account(user[0])
				command = tail
			} else {
				command = rest
			}
		}
		// The command is one shell line; the offset makes its edges report the
		// crontab line they came from.
		edges = append(edges, shellEdges(command, rawEdge{
			surface: SurfaceCron, phase: phase, subject: subject,
			trigger: file.Path, line: index,
		})...)
	}
	return edges
}

// cutWords removes n whitespace-separated words and returns them with the rest
// of the line. The rest keeps its own spacing, so a command's quoting survives.
func cutWords(line string, n int) ([]string, string) {
	words := make([]string, 0, n)
	at := 0
	for len(words) < n {
		for at < len(line) && (line[at] == ' ' || line[at] == '\t') {
			at++
		}
		start := at
		for at < len(line) && line[at] != ' ' && line[at] != '\t' {
			at++
		}
		if start == at {
			break
		}
		words = append(words, line[start:at])
	}
	for at < len(line) && (line[at] == ' ' || line[at] == '\t') {
		at++
	}
	return words, line[at:]
}

// isSystemCrontab reports whether the file states the account in its own
// lines: the two system crontabs and the cron.d drop-ins. A user's spool file
// names the account by its file name instead.
func isSystemCrontab(path string) bool {
	return path == "/etc/crontab" || strings.HasPrefix(path, "/etc/cron.d/") ||
		strings.HasPrefix(path, "/etc/cron.daily/") || strings.HasPrefix(path, "/etc/cron.hourly/") ||
		strings.HasPrefix(path, "/etc/cron.weekly/") || strings.HasPrefix(path, "/etc/cron.monthly/")
}

// cronFileSubject names who a crontab-format file's lines run as when the line
// does not state it. A user spool file's name is the account.
func cronFileSubject(path string) Subject {
	if user, ok := strings.CutPrefix(path, "/var/spool/cron/crontabs/"); ok {
		return Account(filepath.Base(user))
	}
	if rest, ok := strings.CutPrefix(path, "/var/spool/cron/"); ok {
		if !strings.Contains(rest, "/") {
			return Account(rest)
		}
	}
	return Subject{Class: AccountRoot}
}

// cronShellSubject names who a shell file in the cron surface runs as: a
// run-parts script is root's, and an at spool file is the submitting user's.
func cronShellSubject(path string) Subject {
	if strings.HasPrefix(path, "/var/spool/cron/atjobs/") || strings.HasPrefix(path, "/var/spool/at/") {
		return Account("at")
	}
	return Subject{Class: AccountRoot}
}
