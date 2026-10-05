// persistence: cron, boot units, ld.so.preload, shell startup files, at.

package linux

import (
	"time"

	"karma/internal/cluster"
	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
)

var cronScript = script.Lines(
	script.ReadFiles([]string{"/etc/crontab", "/etc/anacrontab"}, `cat "$f"`, true),
	script.ReadFiles([]string{
		"/etc/cron.d/*",
		"/etc/cron.daily/*",
		"/etc/cron.hourly/*",
		"/etc/cron.weekly/*",
		"/etc/cron.monthly/*",
		"/var/spool/cron/crontabs/*",
		"/var/spool/cron/*",
		"/var/spool/cron/atspool/*",
		"/var/spool/cron/atjobs/*",
	}, `cat "$f"`, true),
	`echo "== crontab -l"`,
	"crontab -l 2>/dev/null",
)

// shellRcPaths: home files lead and the global profile layer trails — the
// per-user startup files are the productive surface, the /etc sections are
// usually stock; within each group the shell read order is kept.
var shellRcPaths = []string{
	"/root/.bashrc",
	"/root/.bash_profile",
	"/root/.bash_login",
	"/root/.profile",
	"/root/.bash_logout",
	"/root/.zshrc",
	"/root/.config/fish/config.fish",
	"/home/*/.bashrc",
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

// skelScript: a new user's home is copied wholesale from /etc/skel, so poisoning a
// template once backdoors every new user afterward; the listing section runs
// find -printf (epoch first) and clusters locally to mark modified templates as
// outliers.
var skelScript = script.Lines(
	`echo "== /etc/skel"`,
	script.ListingFind("/etc/skel/", 100),
	script.ReadFiles([]string{
		"/etc/skel/.bashrc",
		"/etc/skel/.profile",
		"/etc/skel/.bash_profile",
		"/etc/skel/.bash_login",
		"/etc/skel/.bash_logout",
		"/etc/skel/.zshrc",
	}, `cat "$f"`, true),
)

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

// udevScript: the writable layers of udev rules: /etc is admin overrides and /run
// is runtime-generated; the /usr and /lib layer is a sea of official rules and is
// not scanned. The listing is sorted by mtime and clustered, and grep catches only
// the three assignment keys that reference external programs.
var udevScript = script.Lines(
	"for d in /etc/udev/rules.d /run/udev/rules.d; do",
	`  echo "== $d"`,
	"  "+script.ListingFind("$d", 40),
	`  grep -rnIE '(RUN|PROGRAM|IMPORT)(\+=|\{|=)' "$d" 2>/dev/null | head -n 100`,
	"done",
)

// motd: motd and update-motd.d are script surfaces run as root on login
// (mainly Ubuntu).

// pthScript: a .pth in site/dist-packages is processed at Python startup, and a
// line starting with import is code; setuptools' two legitimate precedence files
// are excluded on the grep side, so a normal system stays silent.
const pthScript = `
for d in /usr/lib/python3*/dist-packages /usr/lib/python3*/site-packages \
         /usr/local/lib/python3*/dist-packages /usr/local/lib/python3*/site-packages; do
  [ -d "$d" ] || continue
  grep -rnI --include='*.pth' --exclude='distutils-precedence.pth' \
    --exclude='_distutils_system_mod.pth' '^import' "$d" 2>/dev/null
done
`

// generatorsScript: generators are among the very first executables systemd runs
// at boot, and monitoring agents like auditd/sysmon start only after they finish,
// so the static listing is the only forensics surface; on usrmerge systems /lib and
// /usr/lib are the same directory, so readlink dedup avoids doubling the whole thing.
var generatorsScript = script.Lines(
	"seen=",
	"for d in /etc/systemd/system-generators /run/systemd/system-generators \\",
	"         /usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \\",
	"         /lib/systemd/system-generators \\",
	"         /etc/systemd/user-generators /run/systemd/user-generators \\",
	"         /usr/local/lib/systemd/user-generators /usr/lib/systemd/user-generators \\",
	"         /root/.local/share/systemd/user-generators \\",
	"         /home/*/.local/share/systemd/user-generators; do",
	`  [ -d "$d" ] || continue`,
	`  r=$(readlink -f "$d")`,
	`  case " $seen " in *" $r "*) continue;; esac`,
	`  seen="$seen $r"`,
	`  echo "== $d"`,
	"  "+script.ListingFind("$d", 100),
	"done",
)

// PersistenceChecks covers persistence.
var PersistenceChecks = []*model.Check{
	define.LinuxCheck("cron", "Scheduled tasks", model.AspectPersistence,
		[]model.Probe{
			{Label: "cat", Inv: model.Dual{Run: nativeCron, Script: cronScript}},
		},
		define.CheckOpt{
			// pygments has no crontab lexer; the bash lexer approximates the command part well
			// enough
			Syntax: "bash",
			Rules: []model.Rule{
				model.NewRule("cron-reboot", `@reboot\b`, model.High, "cron job run on reboot"),
				model.NewRule("cron-every-minute", `^\s*\*(?:/1)?\s+\*\s+\*\s+\*\s+\*`, model.Medium,
					"cron runs every minute (dwell cadence)"),
				define.KeywordRule,
			},
		}),
	define.LinuxCheck("enabled-units", "Units enabled at boot", model.AspectPersistence,
		[]model.Probe{{Label: "systemctl",
			Inv: model.NewCommand("systemctl", "list-unit-files", "--state=enabled")}},
		define.CheckOpt{
			Filters: []model.LineFilter{
				model.NewFilter("unit-files-header", `^UNIT FILE\b`, model.FilterDrop),
				model.NewFilter("unit-files-listed", `^\d+ unit files listed`, model.FilterDrop),
			},
			Syntax: "table",
		}),
	define.LinuxCheck("rc-local", "rc.local boot script", model.AspectPersistence,
		readFilesCheck("/etc/rc.local", "/etc/rc.d/rc.local"),
		define.CheckOpt{
			Syntax: "bash",
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
	define.LinuxCheck("ld-preload", "Dynamic library preload (ld.so.preload)", model.AspectPersistence,
		[]model.Probe{
			{Label: "cat", Inv: model.Dual{Run: nativeLdPreload, Script: "cat /etc/ld.so.preload 2>/dev/null"}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("preload-entry", `^[^#\n]\S+`, model.High, "preloaded shared library configured"),
			},
		}),
	// ld.so.conf is a list of library search directories whose entries are normally
	// present, so it only gets a LOW hint; kept separate from ld.so.preload so one
	// HIGH rule does not flag the whole directory list.
	define.LinuxCheck("ld-conf", "Dynamic library search path (ld.so.conf)", model.AspectPersistence,
		readFilesCheck("/etc/ld.so.conf", "/etc/ld.so.conf.d/*"),
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("ld-conf-entry", `^[^#\n]\S+`, model.Low, "library search path entry"),
			},
		}),
	define.LinuxCheck("shell-rc", "Shell startup files", model.AspectPersistence,
		readFilesCheck(shellRcPaths...),
		define.CheckOpt{Rules: []model.Rule{historyOffRule, define.KeywordRule}, Syntax: "bash"}),
	define.LinuxCheck("skel", "Home directory templates (/etc/skel)", model.AspectPersistence,
		[]model.Probe{
			{Label: "cat", Inv: model.Dual{Run: nativeSkel, Script: skelScript}},
		},
		define.CheckOpt{
			Syntax:    "bash",
			Normalize: cluster.ListingNormalize(time.Now),
			Rules:     []model.Rule{define.KeywordRule},
			// the listing section speaks ls -l, the collected files speak shell
			SectionSyntax: []model.SectionSyntax{{Title: "/etc/skel", Syntax: "ls-l"}},
		}),
	define.LinuxCheck("at", "at one-shot job queue", model.AspectPersistence,
		[]model.Probe{{Label: "at", Inv: model.NewCommand("atq")}},
		define.CheckOpt{Syntax: "table"}),
	listingCheck("unit-dirs", "systemd unit directories (by mtime)", model.AspectPersistence,
		unitDirs, 100, nil),
	define.LinuxCheck("systemd-generators", "systemd generator directories", model.AspectPersistence,
		[]model.Probe{
			{Label: "find", Inv: model.Dual{Run: nativeGenerators, Script: generatorsScript}},
		},
		define.CheckOpt{
			Syntax:    "ls-l",
			Normalize: cluster.ListingNormalize(time.Now),
			Rules:     []model.Rule{define.KeywordRule},
		}),
	define.LinuxCheck("udev-rules", "udev rules (writable layers)", model.AspectPersistence,
		[]model.Probe{
			{Label: "find", Inv: model.Dual{Run: nativeUdev, Script: udevScript}},
		},
		define.CheckOpt{
			Syntax:    "ls-l",
			Normalize: cluster.ListingNormalize(time.Now),
			Rules: []model.Rule{
				model.NewRule("udev-exec-key", `(?:RUN|PROGRAM|IMPORT)(?:\+=|\{|=)`, model.Medium,
					"udev rule runs external program"),
			},
		}),
	define.LinuxCheck("motd", "motd login banner", model.AspectPersistence,
		readFilesCheck("/etc/motd", "/etc/update-motd.d/*"),
		define.CheckOpt{Syntax: "bash", Rules: []model.Rule{define.KeywordRule}}),
	// setuptools' two legitimate precedence files are already excluded by the
	// collection script, so the rule stays minimal
	define.LinuxCheck("python-pth", "Python .pth injection", model.AspectPersistence,
		[]model.Probe{
			{Label: "grep", Inv: model.Dual{Run: nativePth, Script: pthScript}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("pth-import", `\.pth:[0-9]+:import`, model.High,
					".pth import (runs at python startup)"),
			},
		}),
}
