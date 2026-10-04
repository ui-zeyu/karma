// log: user command history, failed logins, log-directory pointers.
//
// System logs (auth, cron, etc.) are not collected: formats and priorities differ
// and they are bulky, so reading them uniformly has little value -- log-dirs lists
// /var/log and highlights relevant entries, pointing you to read them individually.
package linux

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/samber/lo"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
	"karma/internal/textutil"
)

var (
	syslogTS   = regexp.MustCompile(`^[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} `)
	variedTail = regexp.MustCompile(`\[\d+\]|\bport \d+\b`)
)

// collapseRepeats folds consecutive duplicate log lines into one marked [xN].
//
// The collapse key erases the always-changing bits (timestamp, pid, port) so only
// identical bodies count as duplicates; the first line is kept verbatim and the
// repeat count is marked [xN]. Brute-force floods and CRON session spam collapse
// into a single line. Section titles only enter the body-normalizer signature; the
// collapse key ignores them.
func collapseRepeats(_ string, text string) *model.Shaped {
	collapsed := lo.Map(runsBy(textutil.CollectLines(text), collapseKey), func(run []string, _ int) string {
		if len(run) == 1 {
			return run[0]
		}
		return fmt.Sprintf("%s [x%d]", run[0], len(run))
	})
	return &model.Shaped{Text: strings.Join(collapsed, "\n")}
}

// collapseKey: erase the first syslog timestamp, replace pid and port with N.
func collapseKey(line string) string {
	if loc := syslogTS.FindStringIndex(line); loc != nil {
		line = line[:loc[0]] + line[loc[1]:]
	}
	return variedTail.ReplaceAllString(line, "N")
}

// runsBy groups adjacent same-key elements into runs (itertools.groupby folding).
func runsBy[T any, K comparable](items []T, key func(T) K) [][]T {
	var runs [][]T
	var current K
	for _, item := range items {
		k := key(item)
		switch {
		case len(runs) > 0 && current == k:
			last := len(runs) - 1
			runs[last] = append(runs[last], item)
		default:
			runs = append(runs, []T{item})
		}
		current = k
	}
	return runs
}

var historyScript = script.ReadFiles([]string{
	"/root/.bash_history",
	"/home/*/.bash_history",
	"/root/.zsh_history",
	"/home/*/.zsh_history",
}, `tail -n 400 "$f"`, true)

var viminfoScript = script.ReadFiles([]string{"/root/.viminfo", "/home/*/.viminfo"},
	`tail -n 200 "$f"`, true)

// LogsChecks covers logs.
var LogsChecks = []*model.Check{
	define.LinuxCheck("history", "User command history (tail)", model.AspectLog,
		[]model.Probe{{Label: "tail", Inv: model.Shell{Script: historyScript}}},
		define.CheckOpt{
			Syntax:    "bash",
			Normalize: collapseRepeats,
			Rules:     []model.Rule{define.KeywordRule},
		}),
	define.LinuxCheck("lastb", "Failed login records", model.AspectLog,
		[]model.Probe{{Label: "lastb", Inv: model.NewCommand("lastb", "-n", "400")}},
		define.CheckOpt{Syntax: "table"}),
	define.LinuxCheck("viminfo", "vim command history", model.AspectLog,
		[]model.Probe{{Label: "tail", Inv: model.Shell{Script: viminfoScript}}},
		define.CheckOpt{
			Filters: []model.LineFilter{
				// viminfo is mostly registers and file marks; the command-line history section
				// starts with ":"
				model.NewFilter("viminfo-cmdline", `^:`, model.FilterKeep),
			},
			Rules: []model.Rule{define.KeywordRule},
		}),
	define.ListingCheck("log-dirs", "Log directory listing (by mtime)", model.AspectLog,
		[]string{"/var/log", "/var/log/journal"}, 100,
		[]model.Rule{
			model.NewRule("logdir-middleware",
				`\b(?:nginx|apache2?|httpd|mysql|mariadb|mysqld|redis|postgres(?:ql)?`+
					`|pgsql|mongod(?:b)?|php-fpm|tomcat\d?|elasticsearch|rabbitmq`+
					`|memcached|docker|containerd)\b|\b(?:access|error)\.log\b`,
				model.Low, "common middleware logs (entry point for webshell and intrusion traces)"),
			model.NewRule("logdir-auth", `\b(?:auth\.log|secure|btmp|wtmp|lastlog|faillog|sshd)\b`,
				model.Low, "login and auth records (SSH investigation entry point)"),
			model.NewRule("logdir-cron", `\bcron`, model.Low, "cron logs (persistence investigation)"),
			define.KeywordRule,
		}),
}
