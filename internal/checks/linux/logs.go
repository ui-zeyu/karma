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
	"time"

	"github.com/samber/lo"

	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/model"
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

// historyPaths: bash, zsh, and fish histories under root and every home —
// fish stores its history as YAML (`- cmd: …`) under the data directory.
var historyPaths = []string{
	"/root/.bash_history",
	"/home/*/.bash_history",
	"/root/.zsh_history",
	"/home/*/.zsh_history",
	"/root/.local/share/fish/fish_history",
	"/home/*/.local/share/fish/fish_history",
}

// lastbRows is how far back the failed-login history reads: `lastb -n` on the
// target, the same window of the in-process btmp read.
const lastbRows = 400

// The settings and commands that silence command history. The history file
// keeps earlier lines, so a hit is a present-tense signal.
var historyOffRule = model.NewRule("history-off",
	`\b(?:HISTFILE=/dev/null|HISTSIZE=0|HISTFILESIZE=0)\b|(?i)\bunset\s+HISTFILE\b`,
	model.Medium, "command history recording turned off")

// Clearing wipes only the current shell; the history file still holds what came
// before.
var historyClearRule = model.NewRule("history-clear", `\bhistory\s+-c\b`, model.Medium,
	"history cleared (earlier lines kept)")

// accessLogPaths: the request logs of the two web server layouts, the current
// file and the first rotation each — the rotation is where the attack day often
// sits once the site has been up for a while. Per-vhost logs and the compressed
// rotations stay out: the list is fixed so the summary costs the same on every
// host, and karma's built-in readers can reach a specific file on request.
var accessLogPaths = []string{
	"/var/log/apache2/access.log",
	"/var/log/apache2/access.log.1",
	"/var/log/apache2/other_vhosts_access.log",
	"/var/log/httpd/access_log",
	"/var/log/nginx/access.log",
	"/var/log/nginx/access.log.1",
}

// The access-log vocabulary. The keep pattern below is one POSIX ERE — the
// target's awk reads it, so it carries no RE2-only syntax (no \b, no (?:), and
// it is matched against the lowercased line) — and the rules are built from the
// same lists, so a tool name or a parameter cannot be in one and missing from
// the other.
var (
	// accessLogTools name themselves in a User-Agent or in a path.
	accessLogTools = []string{
		"sqlmap", "nuclei", "fscan", "masscan", "nikto", "dirbuster", "gobuster",
		"wpscan", "hydra", "zgrab", "nessus", "acunetix", "xray",
	}
	// accessLogParams carry a command, a file or a credential: in a log the
	// exploit payload arrives URL-encoded, so the eval-shaped webshell rules
	// never see it and the parameter name is what is left.
	accessLogParams = []string{
		"cmd", "exec", "system", "shell", "eval", "assert",
		"upload", "include", "passwd", "password", "key",
	}
	// accessLogFiles are the install, backup and console artifacts a probe
	// asks for, plus the suffixes of a dumped file.
	accessLogFiles = []string{
		"install", "readme", "backup", "dump", "wp-login.php",
		"phpmyadmin", "adminer", "manager/html", "actuator", "solr/admin",
	}
	// accessLogTraversal covers the whole run of hops, so the paint is the
	// traversal the reason names rather than its first step.
	accessLogTraversal = `((\.\./)+|%2e%2e)`
	accessLogDotDirs   = `\.(git|env|svn|ssh)/`
	accessLogSuffixes  = `\.(sql|zip|tar\.gz|bak|old|swp|save|env|git)`
)

// accessLogKeep is the one pattern the collection keeps request lines by; the
// rules below grade exactly its arms, so a line in the panel always has a
// reason.
var accessLogKeep = `(` + accessLogTraversal + `|` + accessLogDotDirs +
	`|[?&](` + strings.Join(accessLogParams, "|") + `)=|(` +
	strings.Join(accessLogTools, "|") + `)|/(` + strings.Join(accessLogFiles, "|") +
	`)|` + accessLogSuffixes + `)`

// accessLogKeepRe is the reader side of accessLogKeep; the (?i) is the awk
// pass's tolower.
var accessLogKeepRe = regexp.MustCompile(`(?i)` + accessLogKeep)

var (
	logScanToolRule = model.NewRule("log-scan-tool",
		`(?i)\b(?:`+strings.Join(accessLogTools, "|")+`)\b`, model.High,
		"scanner or attack tool in the request log")
	logTraversalRule = model.NewRule("log-traversal", accessLogTraversal, model.High,
		"path traversal in a request")
	logExecParamRule = model.NewRule("log-exec-param",
		`(?i)[?&](?:`+strings.Join(accessLogParams, "|")+`)=`, model.High,
		"command, file or credential parameter in a request URL")
	logSensitiveFileRule = model.NewRule("log-sensitive-file",
		`(?i)/(?:`+strings.Join(accessLogFiles, "|")+`)|`+accessLogDotDirs+`|`+accessLogSuffixes,
		model.Medium, "install, backup or console file requested")
)

const accessLogTimeout = 60 * time.Second // six windows read and counted on the target

// accessLogLines caps the summary: three tables per file plus the request
// lines worth reading, past which the log has only volume left.
const accessLogLines = 400

// LogsChecks covers logs.
var LogsChecks = []*model.Check{
	define.LinuxCheck("history", "User command history (tail)", model.AspectLog,
		tailFilesCheck(400, historyPaths...),
		define.CheckOpt{
			Syntax:    model.SyntaxBash,
			Normalize: collapseRepeats,
			Rules:     []model.Matcher{historyOffRule, historyClearRule, define.KeywordRule},
		}),
	define.LinuxCheck("viminfo", "vim command history", model.AspectLog,
		tailFilesCheck(200, "/root/.viminfo", "/home/*/.viminfo"),
		define.CheckOpt{
			Filters: []model.LineFilter{
				// viminfo is mostly registers and file marks; the command-line history section
				// starts with ":"
				model.NewFilter("viminfo-cmdline", `^:`, model.FilterKeep),
			},
			Rules: []model.Matcher{define.KeywordRule},
		}),
	define.LinuxCheck("lastb", "Failed login records", model.AspectLog,
		[]model.Step{{{Label: "lastb", Inv: model.Native{Body: native.Lastb(lastbRows)}}}},
		define.CheckOpt{Syntax: model.SyntaxTable}),
	listingCheck("log-dirs", "Log directory listing (by mtime)", model.AspectLog,
		[]string{"/var/log", "/var/log/journal"}, 100,
		[]model.Matcher{
			model.NewRule("logdir-middleware",
				`\b(?:nginx|apache2?|httpd|mysql|mariadb|mysqld|redis|postgres(?:ql)?`+
					`|pgsql|mongod(?:b)?|php-fpm|tomcat\d?|elasticsearch|rabbitmq`+
					`|memcached|docker|containerd)\b|\b(?:access|error)\.log\b`,
				model.Low, "common middleware logs (entry point for webshell and intrusion traces)"),
			model.NewRule("logdir-auth", `\b(?:auth\.log|secure|btmp|wtmp|lastlog|faillog|sshd)\b`,
				model.Low, "login/auth records (SSH entry point)"),
			model.NewRule("logdir-cron", `\bcron`, model.Low, "cron logs (persistence trail)"),
			define.KeywordRule,
		}),
	// The summary itself is context — who hammered the host and when — and the
	// request lines it carries are the findings, so the keep pattern and the
	// rules are one vocabulary.
	define.LinuxCheck("access-log", "Web access log summary (clients, minutes, probes)", model.AspectLog,
		[]model.Step{{{Label: "log", Inv: model.Native{Body: native.AccessLog(accessLogPaths, accessLogKeepRe)}, Cap: model.Scan(accessLogLines)}}},
		define.CheckOpt{
			Rules: []model.Matcher{
				logScanToolRule, logTraversalRule, logExecParamRule, logSensitiveFileRule,
			},
			Timeout: accessLogTimeout,
		}),
}
