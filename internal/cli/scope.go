package cli

import (
	"fmt"
	"strconv"
	"strings"

	"karma/internal/audit"
)

// scope is the positional narrowing: activation surfaces, paths, and pids.
type scope struct {
	surfaces map[string]bool // nil means every surface
	paths    []string
	exclude  []string
	pids     map[int]bool
}

var surfaceWords = []string{
	"systemd", "profile", "init", "cron", "loader", "udev",
	"ssh", "pam", "supervisor", "xdg", "apt", "module", "activity", "authority",
}

var surfaceGroups = map[string][]string{
	"persistence": {"systemd", "profile", "init", "cron", "loader", "udev", "ssh", "pam", "supervisor", "xdg", "apt", "module"},
	"boot":        {"systemd", "init", "loader", "udev", "apt", "module"},
	"login":       {"profile", "ssh", "pam", "xdg"},
	"schedule":    {"cron"},
	"service":     {"systemd", "supervisor"},
	"device":      {"udev"},
	"activity":    {"activity"},
}

func parseScope(words []string) (scope, error) {
	parsed := scope{}
	for _, word := range words {
		excluded := strings.HasPrefix(word, "!")
		name := strings.TrimPrefix(word, "!")
		if name == "" {
			return scope{}, fmt.Errorf("an exclusion needs a word after \"!\"")
		}
		if strings.HasPrefix(name, "/proc/") {
			pid, err := strconv.Atoi(strings.TrimPrefix(name, "/proc/"))
			if err != nil {
				return scope{}, fmt.Errorf("unknown process %q", name)
			}
			if parsed.pids == nil {
				parsed.pids = map[int]bool{}
			}
			parsed.pids[pid] = !excluded
			continue
		}
		if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "./") || strings.HasPrefix(name, "~/") {
			if excluded {
				parsed.exclude = append(parsed.exclude, name)
			} else {
				parsed.paths = append(parsed.paths, name)
			}
			continue
		}
		names, ok := surfaceGroups[name]
		if !ok {
			if !contains(surfaceWords, name) {
				return scope{}, fmt.Errorf("unknown scope %q (surfaces: %s)", name, strings.Join(surfaceWords, ", "))
			}
			names = []string{name}
		}
		if parsed.surfaces == nil {
			parsed.surfaces = map[string]bool{}
			if excluded {
				for _, surface := range surfaceWords {
					parsed.surfaces[surface] = true
				}
			}
		}
		for _, surface := range names {
			parsed.surfaces[surface] = !excluded
		}
	}
	return parsed, nil
}

func (s scope) filter(min audit.Severity) audit.Filter {
	return audit.Filter{
		Surfaces:     s.surfaces,
		Paths:        s.paths,
		ExcludePaths: s.exclude,
		PIDs:         s.pids,
		MinSeverity:  min,
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
