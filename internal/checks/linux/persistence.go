// persistence: cron, boot units, ld.so.preload, shell startup files, at.

package linux

import (
	"regexp"

	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/model"
)

// cronPaths: the two system crontabs, then the spool and cron.d layers; the
// ssh loop and the local walk read the same list in the same order.
var cronPaths = []string{
	"/etc/crontab", "/etc/anacrontab",
	"/etc/cron.d/*",
	"/etc/cron.daily/*",
	"/etc/cron.hourly/*",
	"/etc/cron.weekly/*",
	"/etc/cron.monthly/*",
	"/var/spool/cron/crontabs/*",
	"/var/spool/cron/*",
	"/var/spool/cron/atspool/*",
	"/var/spool/cron/atjobs/*",
}

// bootScriptPaths are the boot-time scripts the rc-local check reads: the classic
// SysV hook at both of its locations (Debian and RedHat families) and the
// init.sh that cloud images and appliances run from rc.local or an init unit. A
// path dropped from this list is invisible at run time — the file simply stops
// appearing in the report — so the list is pinned by a test.
var bootScriptPaths = []string{"/etc/rc.local", "/etc/rc.d/rc.local", "/etc/init.sh"}

// shellRcPaths: home files lead and the global profile layer trails — the
// per-user startup files are the productive surface, the /etc sections are
// usually stock; within each group the shell read order is kept. .bash_aliases
// is read next to .bashrc because that is what sources it: an alias is session
// state until it is written there, and an alias is how a command the analyst
// trusts is made to lie.
var shellRcPaths = []string{
	"/root/.bashrc",
	"/root/.bash_aliases",
	"/root/.bash_profile",
	"/root/.bash_login",
	"/root/.profile",
	"/root/.bash_logout",
	"/root/.zshrc",
	"/root/.config/fish/config.fish",
	"/home/*/.bashrc",
	"/home/*/.bash_aliases",
	"/home/*/.bash_profile",
	"/home/*/.bash_login",
	"/home/*/.profile",
	"/home/*/.bash_logout",
	"/home/*/.zshrc",
	"/home/*/.config/fish/config.fish",
	"/etc/profile",
	"/etc/profile.d/*",
	"/etc/bashrc",
	"/etc/bash.bashrc",
	"/etc/bash.bash_logout",
	"/etc/zsh/zshrc",
	"/etc/zprofile",
	"/etc/fish/config.fish",
}

// skelDir, skelHead and skelTemplates are the template check's shape: the
// listing and the template files the ssh script and the local walk both cover. A
// new user's home is copied wholesale from /etc/skel, so poisoning one template
// backdoors every new user afterwards; the listing section clusters locally so a
// modified template shows up as an outlier.
const (
	skelDir  = "/etc/skel"
	skelHead = 100
)

var skelTemplates = []string{
	skelDir + "/.bashrc",
	skelDir + "/.profile",
	skelDir + "/.bash_profile",
	skelDir + "/.bash_login",
	skelDir + "/.bash_logout",
	skelDir + "/.zshrc",
}

// unitDirs: a freshly dropped malicious unit floats to the top; /run is tmpfs and
// is cleared on reboot, so malware likes it for volatile persistence. A glob with
// no match stays literal, and a directory find cannot reach is an empty section
// that the reader discards.
var unitDirs = []string{
	"/etc/systemd/system",
	"/etc/systemd/system/*.wants",
	"/run/systemd/system",
	"/etc/systemd/user",
	"/root/.config/systemd/user",
	"/home/*/.config/systemd/user",
}

// udevDirs, udevHead, udevExecMaxHits and udevExec are the udev check's shape:
// the writable rule layers (/etc is admin overrides and /run is
// runtime-generated; the /usr and /lib layer is a sea of official rules and is
// not scanned), the per-layer listing cap, the cap on the assignment-key hits,
// and the keys that reference an external program. The ssh grep and the local
// walk take the same four, so the two channels cover identical rules.
var udevDirs = []string{"/etc/udev/rules.d", "/run/udev/rules.d"}

const (
	udevHead        = 40
	udevExecMaxHits = 100
	udevExec        = `(RUN|PROGRAM|IMPORT)(\+=|\{|=)`
)

var udevExecRe = regexp.MustCompile(udevExec)

// motd: motd and update-motd.d are script surfaces run as root on login
// (mainly Ubuntu).

// generatorDirs and generatorHead are the generator check's shape: the directory
// word list and the per-directory listing cap, which the ssh script and the local
// walk both take. Generators are among the very first executables systemd runs at
// boot, and monitoring agents like auditd/sysmon start only after they finish, so
// the static listing is the only forensics surface; on usrmerge systems /lib and
// /usr/lib are the same directory, so readlink dedup avoids doubling the whole thing.
var generatorDirs = []string{
	"/etc/systemd/system-generators",
	"/run/systemd/system-generators",
	"/usr/local/lib/systemd/system-generators",
	"/usr/lib/systemd/system-generators",
	"/lib/systemd/system-generators",
	"/etc/systemd/user-generators",
	"/run/systemd/user-generators",
	"/usr/local/lib/systemd/user-generators",
	"/usr/lib/systemd/user-generators",
	"/root/.local/share/systemd/user-generators",
	"/home/*/.local/share/systemd/user-generators",
}

const generatorHead = 100

// aliasShadowRule marks an alias that redefines a tool the analyst reads the
// host with. `alias netstat=…` makes the connection table whatever the line
// says, and BlackCat pointed `cat` at a file named -t so a UID 0 account stayed
// out of /etc/passwd output. The alias's value is graded by the global rules;
// this rule names the shape. The Debian-family colour aliases are the same
// shape on every stock host, so their --color marker suppresses the line.
var aliasShadowRule = model.NewRule("alias-command-shadow",
	`\balias[ \t]+(?:cat|ls|ps|netstat|ss|find|grep|top|lsof|stat|md5sum|sha1sum|sha256sum`+
		`|lsmod|crontab|systemctl|journalctl|id|who|w|last|lastlog|df|du|ip|ifconfig|arp`+
		`|route|file|pgrep|pkill|kill)[ \t]*=`,
	model.Medium, "alias redefines a system inspection command").WithExclude(`--color`)

// PersistenceChecks covers persistence.
var PersistenceChecks = []*model.Check{
	define.LinuxCheck("cron", "Scheduled tasks", model.AspectPersistence,
		[]model.Step{{{Label: "cat", Inv: model.Native{Body: native.Cron(cronPaths)}}}},
		define.CheckOpt{
			// pygments has no crontab lexer; the bash lexer approximates the command part well
			// enough
			Syntax: model.SyntaxBash,
			Rules: []model.Rule{
				model.NewRule("cron-reboot", `@reboot\b`, model.High, "cron job run on reboot"),
				model.NewRule("cron-every-minute", `^\s*\*(?:/1)?\s+\*\s+\*\s+\*\s+\*`, model.Medium,
					"cron runs every minute (dwell cadence)"),
				define.KeywordRule,
			},
		}),
	define.LinuxCheck("at", "at one-shot job queue", model.AspectPersistence,
		[]model.Step{{{Label: "at", Inv: model.NewCommand("atq")}}},
		define.CheckOpt{Syntax: model.SyntaxTable}),
	define.LinuxCheck("enabled-units", "Units enabled at boot", model.AspectPersistence,
		[]model.Step{{{Label: "systemctl",
			Inv: model.NewCommand("systemctl", "list-unit-files", "--state=enabled")}}},
		define.CheckOpt{
			Filters: []model.LineFilter{
				model.NewFilter("unit-files-header", `^UNIT FILE\b`, model.FilterDrop),
				model.NewFilter("unit-files-listed", `^\d+ unit files listed`, model.FilterDrop),
			},
			// The row carries two state words — the unit's own and the vendor
			// preset — and the unit-files lexer paints each by its value
			// (enabled apart from disabled), where the generic table styler
			// would only cycle columns.
			Syntax: model.SyntaxUnitFiles,
		}),
	listingCheck("unit-dirs", "systemd unit directories (by mtime)", model.AspectPersistence,
		unitDirs, 100, nil),
	define.LinuxCheck("systemd-generators", "systemd generator directories", model.AspectPersistence,
		[]model.Step{{{Label: "find", Inv: model.Native{Body: native.Generators(generatorDirs, generatorHead)}}}},
		define.CheckOpt{
			Syntax:    model.SyntaxLsL,
			Normalize: listingNormalize,
			Rules:     []model.Rule{define.KeywordRule},
		}),
	define.LinuxCheck("rc-local", "Boot scripts (rc.local, init.sh)", model.AspectPersistence,
		readFilesCheck(bootScriptPaths...),
		define.CheckOpt{
			Syntax: model.SyntaxBash,
			Rules: []model.Rule{
				model.NewRule("rc-b64-shell", `\bbase64\b[^|\n]*\|\s*[^|\n]*\b(?:ba|z|da|k)?sh\b`,
					model.High, "base64 piped to shell (at boot)"),
				model.NewRule("rc-b64-decode", `\bbase64\s+(?:-[A-Za-z]+\s+)*-d\b`, model.Medium,
					"base64 decode execution trace"),
				define.KeywordRule,
			},
		}),
	// Trailing slash dereferences: on RedHat-family systems /etc/init.d is a symlink
	// to rc.d/init.d. The runlevel directories (rc0.d…rc6.d) hold the same links
	// multiplied by runlevel, so they would flood the report for little extra signal;
	// the dropped script itself lands in init.d and the boot-time layer is rcS.d.
	listingCheck("sysv-init", "SysV init scripts", model.AspectPersistence,
		[]string{"/etc/init.d/", "/etc/rc.d", "/etc/rcS.d"}, 100,
		[]model.Rule{define.KeywordRule}),
	listingCheck("xinetd", "xinetd service directory", model.AspectPersistence,
		[]string{"/etc/xinetd.d"}, 100, []model.Rule{define.KeywordRule}),
	define.LinuxCheck("udev-rules", "udev rules (writable layers)", model.AspectPersistence,
		[]model.Step{{{Label: "find", Inv: model.Native{Body: native.Udev(udevDirs, udevHead, udevExecMaxHits, udevExecRe)}}}},
		define.CheckOpt{
			Syntax:    model.SyntaxLsL,
			Normalize: listingNormalize,
			Rules: []model.Rule{
				// The span carries the key and the value it runs (RUN+="…",
				// IMPORT{program}="…"): the command is the finding, and the span is
				// what the panel paints.
				model.NewRule("udev-exec-key",
					`(?:RUN|PROGRAM|IMPORT)(?:\{[^}\n]*\})?\+?=(?:"[^"\n]*"|\S*)`, model.Medium,
					"udev rule runs external program"),
			},
		}),
	define.LinuxCheck("ld-preload", "Dynamic library preload (ld.so.preload)", model.AspectPersistence,
		[]model.Step{{{Label: "cat", Inv: model.Native{Body: native.LdPreload}}}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("preload-entry", `^[^#\n]\S+`, model.Critical, "preloaded shared library configured"),
			},
		}),
	// ld.so.conf is a list of library search directories whose entries are normally
	// present, so it only gets a LOW hint; kept separate from ld.so.preload so one
	// CRITICAL rule does not flag the whole directory list.
	define.LinuxCheck("ld-conf", "Dynamic library search path (ld.so.conf)", model.AspectPersistence,
		readFilesCheck("/etc/ld.so.conf", "/etc/ld.so.conf.d/*"),
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("ld-conf-entry", `^[^#\n]\S+`, model.Low, "library search path entry"),
			},
		}),
	define.LinuxCheck("shell-rc", "Shell startup files", model.AspectPersistence,
		readFilesCheck(shellRcPaths...),
		define.CheckOpt{
			Rules:  []model.Rule{aliasShadowRule, historyOffRule, define.KeywordRule},
			Syntax: model.SyntaxBash,
		}),
	define.LinuxCheck("skel", "Home directory templates (/etc/skel)", model.AspectPersistence,
		[]model.Step{{{Label: "cat", Inv: model.Native{Body: native.Skel(skelDir, skelHead, skelTemplates)}}}},
		define.CheckOpt{
			Syntax:    model.SyntaxBash,
			Normalize: listingNormalize,
			Rules:     []model.Rule{define.KeywordRule},
			// the listing section speaks ls -l, the collected files speak shell
			SectionSyntax: []model.SectionSyntax{{Title: "/etc/skel", Syntax: model.SyntaxLsL}},
		}),
	define.LinuxCheck("motd", "motd login banner", model.AspectPersistence,
		readFilesCheck("/etc/motd", "/etc/update-motd.d/*"),
		define.CheckOpt{Syntax: model.SyntaxBash, Rules: []model.Rule{define.KeywordRule}}),
}
