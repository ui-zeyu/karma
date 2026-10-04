// filesystem: disks and files: mounts, temp directories, SUID/SGID and content
// signatures under web directories.

package linux

import (
	"slices"
	"strings"
	"time"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
)

const suidFind = "find / -xdev -perm -4000 -type f 2>/dev/null"
const suidTimeout = 25 * time.Second

const sgidFind = "find / -xdev -perm -2000 -type f 2>/dev/null"

// gtfobinsSu is the full basename list of SUID privilege-escalation programs from
// GTFOBins: taken 2026-10-02 from github.com/GTFOBins/GTFOBins.github.io's
// _gtfobins/* (included if any example context carries suid, 308 entries). The
// list holds basenames only, and version suffixes are tolerated uniformly by
// gtfobinsPattern (python matches python3.x); the names contain no regex
// metacharacters except the dot, which is escaped literally. To regenerate: clone
// the repo and collect the 6-space-indented suid: keys.
var gtfobinsSu = []string{
	"aa-exec", "ab", "acr", "agetty", "alpine", "apache2", "apt-get", "ar", "aria2c",
	"arj", "arp", "as", "ascii-xfr", "ash", "aspell", "asterisk", "atobm", "aws",
	"base32", "base64", "basenc", "basez", "bash", "batcat", "bc", "bconsole", "bee",
	"bridge", "busctl", "bzip2", "cabal", "cancel", "capsh", "cat", "chattr", "chmod",
	"choom", "chown", "chroot", "chrt", "clamscan", "clisp", "cmp", "cobc", "column",
	"comm", "cp", "cpio", "cpulimit", "crash", "csh", "csplit", "csvtool", "ctr",
	"cupsfilter", "curl", "cut", "dash", "date", "dc", "dd", "debugfs", "dialog",
	"diff", "dig", "distcc", "dmesg", "dmsetup", "dnsmasq", "docker", "dos2unix",
	"dosbox", "dpkg", "dvips", "easyrsa", "ed", "efax", "egrep", "elvish", "enscript",
	"env", "eqn", "espeak", "ex", "expand", "expect", "fastfetch", "ffmpeg", "fgrep",
	"file", "find", "finger", "fish", "flock", "fmt", "fold", "forge", "fping",
	"ftp", "fzf", "gawk", "gcloud", "gcore", "gdb", "genie", "genisoimage", "getent",
	"ginsh", "git", "gnuplot", "grep", "gtester", "guile", "gzip", "head", "hexdump",
	"hg", "highlight", "hping3", "iconv", "iftop", "install", "ionice", "ip", "ispell",
	"joe", "join", "jq", "jrunscript", "julia", "ksshell", "kubectl", "last", "latex",
	`ld\.so`, "ldconfig", "less", "lftp", "links", "logrotate", "logsave", "look",
	"lp", "ltrace", "lua", "lualatex", "luatex", "lxd", "m4", "mail", "make", "man",
	"mawk", "minicom", "more", "mosquitto", "msgattrib", "msgcat", "msgconv",
	"msgfilter", "msgmerge", "msguniq", "multitime", "mv", "mysql", "nano", "nasm",
	"nc", "ncdu", "ncftp", "nginx", "nice", "nl", "nm", "nmap", "node", "nohup",
	"nsenter", "ntpdate", "octave", "od", "opencode", "openssl", "openvpn", "pandoc",
	"paste", "pax", "pdflatex", "pdftex", "perf", "perl", "pexec", "pg", "php",
	"pic", "pidstat", "plymouth", "pr", "psftp", "psql", "ptx", "python", "qpdf",
	"R", "rc", "readelf", "redis", "restic", "rev", "rlogin", "rlwrap", "rpm",
	"rpmdb", "rpmquery", "rpmverify", "rsync", "rtorrent", "run-parts", "runscript",
	"sash", "scanmem", "scp", "script", "scrot", "sed", "setarch", "setcap", "setfacl",
	"setlock", "sftp", "shred", "shuf", "slsh", "socat", "socket", "soelim",
	"softlimit", "sort", "split", "sqlite3", "ss", "ssh", "ssh-agent", "ssh-keygen",
	"ssh-keyscan", "sshpass", "start-stop-daemon", "stdbuf", "strace", "strings",
	"sysctl", "systemctl", "tac", "tail", "tar", "task", "tasksh", "tbl", "tclsh",
	"tcpdump", "tcsh", "tdbtool", "tee", "telnet", "terraform", "tex", "tftp", "tic",
	"time", "timeout", "tmate", "tmux", "troff", "ul", "unexpand", "uniq", "unshare",
	"unsquashfs", "unzip", "update-alternatives", "urlget", "uuencode", "varnishncsa",
	"vi", "vigr", "vim", "vipw", "volatility", "w3m", "watch", "wc", "wget", "whiptail",
	"whois", "wish", "xargs", "xdotool", "xmodmap", "xmore", "xpad", "xxd", "xz",
	"yash", "zic", "zip", "zless", "zsh", "zsoelim",
}

// gtfobinsPattern: the list holds basenames only and version suffixes are tolerated
// uniformly after the alternation: python matches python3.x without crossing a
// hyphen to wrongly hit things like python-config.
var gtfobinsPattern = `/(?:[\w.]+/)*(?:` + strings.Join(slices.Sorted(slices.Values(gtfobinsSu)), "|") + `)[0-9.]*$`

var tmpDirs = []string{"/tmp", "/var/tmp", "/dev/shm"}

const webScriptFind = "find /var/www /usr/local/nginx /opt -xdev -maxdepth 3 -type f" +
	` \( -name '*.php' -o -name '*.jsp' -o -name '*.jspx' -o -name '*.sh' -o -name '*.py' \)` +
	" -mtime -14 2>/dev/null"
const webTimeout = 15 * time.Second

// Three webshell signature groups: request superglobals passed straight into an
// exec/decode/callback function. The same regex feeds both grep -e (target-side
// line filtering) and the local rules (severity by group); case is opened on both
// sides (PHP function names are case-insensitive, the D-Shield convention). [$]
// matches a literal $, working for both grep and re; only plain capture groups are
// used -- GNU grep 3.12 parses (?: literally and the first branch fails to match.
const webshellDirect = `@?\b(eval|assert|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)` +
	`\s*\(\s*[$]_(POST|GET|REQUEST|COOKIE|SERVER|FILES)`
const webshellDecode = `@?\b(eval|assert)\s*\(\s*` +
	`(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|convert_uudecode)\s*[(]`
const webshellCallback = `@?\b(call_user_func(_array)?|create_function|array_map|array_filter|usort|uasort` +
	`|register_shutdown_function|extract|parse_str|mb_ereg_replace)` +
	`\s*\(\s*[$]_(POST|GET|REQUEST|COOKIE)`

// webshellGrep's directory list matches web-dirs plus the common AWD roots /srv,
// /app and /usr/share/nginx; .git/node_modules only slow the walk and yield no hits.
const webshellGrep = "grep -rInEi --include='*.php' --include='*.phtml' --include='*.inc'" +
	" --exclude-dir=.git --exclude-dir=node_modules" +
	" -e '" + webshellDirect + "' -e '" + webshellDecode + "' -e '" + webshellCallback + "'" +
	" /var/www /srv /opt /app /usr/local/nginx /usr/share/nginx 2>/dev/null"

// keyDirs: listing collection runs find -printf (epoch first, body in ls -l shape)
// and clusters locally to mark outlier lines with !/!!; find lists dotfiles
// naturally, so the hidden subsection is dropped.
var keyDirs = []string{"/", "/home", "/opt", "/root", "/srv", "/usr/local"}

// homeTreeFind: the whole /home tree, four levels deep (down to files in home
// directories, deeper project trees truncated); tree is used if present, else 127
// falls through to find. find's -printf is arranged in ls -l shape, which the ls-l
// pseudo-lexer colors directly.
const homeTreeArgs = "-a -p -u -g -s -D --timefmt '%Y-%m-%d %H:%M' -L 4"

var homeTreeFind = "LC_ALL=C find /home -xdev -maxdepth 4 -printf '" + script.LSBodyPrintf + "' 2>/dev/null"

// mountNoise: snap/container overlay mounts are noise during host incident response.
const mountNoise = `\b(?:squashfs|overlay)\b|/dev/loop\d+`

var mountRemoteFsRule = model.NewRule("mount-remote-fs", `\b(?:nfs\d?|cifs|sshfs)\b`,
	model.Low, "network filesystem mount")

// sshMaterialRule is shared entry highlighting for listing-style checks: SSH key
// material and tunnel/proxy tools.
var sshMaterialRule = model.NewRule("ssh-material",
	`\.ssh\b|\bauthorized_keys\d?\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\bknown_hosts\b`,
	model.Low, "SSH key/authorization file entry")

var tunnelToolRule = model.NewRule("tunnel-tool",
	`\bfrps?c?\b|\bnps\b|\bnpc\b|\bchisel\b|\bgost\b|\biox\b|\bngrok\b|\bsuo5\b`,
	model.Medium, "tunnel/proxy tool (frp/ngrok/chisel)")

// FilesystemChecks covers disks and files.
var FilesystemChecks = []*model.Check{
	define.LinuxCheck("df", "Disk usage", model.AspectFilesystem,
		[]model.Probe{{Label: "df", Inv: model.NewCommand("df", "-h")}},
		define.CheckOpt{Syntax: "df"}),
	define.LinuxCheck("fstab", "Filesystem mount config (fstab)", model.AspectFilesystem,
		[]model.Probe{{Label: "cat", Inv: model.Shell{Script: "cat /etc/fstab 2>/dev/null"}}},
		define.CheckOpt{Syntax: "fstab", Rules: []model.Rule{mountRemoteFsRule}}),
	define.LinuxCheck("mounts", "Mount points", model.AspectFilesystem,
		[]model.Probe{
			{Label: "findmnt", Inv: model.NewCommand("findmnt")},
			{Label: "mount", Inv: model.NewCommand("mount")},
		},
		define.CheckOpt{
			Filters: []model.LineFilter{
				model.NewFilter("mount-noise", mountNoise, model.FilterDrop),
			},
			Syntax: "table",
			Rules:  []model.Rule{mountRemoteFsRule},
		}),
	define.ListingCheck("tmp-listing", "Temp directory listing", model.AspectFilesystem, tmpDirs, 200,
		[]model.Rule{
			// RE2 has no lookahead: standard system hidden entries (socket directories like
			// .X11-unix, display locks) become an exclusion
			model.NewRule("tmp-hidden-entry", `\s\.[A-Za-z0-9_][A-Za-z0-9_.-]*(?:\s|$)`,
				model.High, "hidden entry in temp directory").
				WithExclude(`\s\.(?:(?:X11|ICE|font|XIM|Test)-unix|X[0-9]+-lock)[A-Za-z0-9_.-]*(?:\s|$)`),
			sshMaterialRule,
			tunnelToolRule,
			define.KeywordRule,
		}),
	// GTFOBins is the only verdict surface on these listings: a documented
	// escalation program under SUID/SGID is critical/high, everything else is
	// quiet evidence (GTFOBins has no separate sgid list, so the suid names
	// stand in).
	define.LinuxCheck("suid", "SUID files", model.AspectFilesystem,
		[]model.Probe{{Label: "find", Inv: model.Shell{Script: suidFind}}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("suid-gtfobins", gtfobinsPattern, model.Critical,
					"SUID privilege-escalation program in GTFOBins"),
			},
			Timeout: suidTimeout,
		}),
	define.LinuxCheck("sgid", "SGID files", model.AspectFilesystem,
		[]model.Probe{{Label: "find", Inv: model.Shell{Script: sgidFind}}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("sgid-gtfobins", gtfobinsPattern, model.High,
					"SGID of a GTFOBins privilege-escalation program (group escalation)"),
			},
			Timeout: suidTimeout,
		}),
	define.ListingCheck("key-dirs", "Key directory listing (by mtime)", model.AspectFilesystem,
		keyDirs, 100, []model.Rule{sshMaterialRule, tunnelToolRule, define.KeywordRule}),
	define.LinuxCheck("home-tree", "/home directory tree (four levels deep, including hidden files)", model.AspectFilesystem,
		[]model.Probe{
			{Label: "tree", Inv: model.Shell{Script: "tree " + homeTreeArgs + " /home 2>/dev/null"}},
			{Label: "find", Inv: model.Shell{Script: homeTreeFind}},
		},
		define.CheckOpt{
			Syntax: "ls-l",
			Rules:  []model.Rule{sshMaterialRule, tunnelToolRule, define.KeywordRule},
		}),
	define.LinuxCheck("web-dirs", "Recently changed scripts in web directories", model.AspectFilesystem,
		[]model.Probe{{Label: "find", Inv: model.Shell{Script: webScriptFind}, LineLimit: 200}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("web-script", `\.(?:php[3-5]?|phtml|jsp|jspx|sh|py)$`, model.Medium,
					"recently changed web script"),
				define.KeywordRule,
			},
			Timeout: webTimeout,
		}),
	// grep and the rules share one signature regex: filter lines on the target, grade
	// by group locally
	define.LinuxCheck("webshell-grep", "Webshell content signatures", model.AspectFilesystem,
		[]model.Probe{{Label: "grep", Inv: model.Shell{Script: webshellGrep}, LineLimit: 200}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("webshell-direct", `(?i)`+webshellDirect, model.Critical,
					"request parameter passed straight into an exec function (one-liner webshell shape)"),
				model.NewRule("webshell-decode", `(?i)`+webshellDecode, model.High,
					"decode function passed straight into eval/assert (common AV-evading webshell shape)"),
				model.NewRule("webshell-callback", `(?i)`+webshellCallback, model.Medium,
					"request parameter into a callback/variable-override function (variant webshell and variable override)"),
			},
			Timeout: webTimeout,
		}),
	// Capabilities are another escalation path besides SUID: cap_setuid equals SUID
	define.LinuxCheck("caps", "File capabilities (getcap)", model.AspectFilesystem,
		[]model.Probe{{Label: "getcap", Inv: model.Shell{Script: "getcap -r / 2>/dev/null"},
			Requires: []string{"getcap"}, LineLimit: 200}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("caps-setuid", `cap_setuid[+=]`, model.Critical,
					"cap_setuid (SUID-equivalent)"),
				model.NewRule("caps-present", `\bcap_[a-z_]+`, model.Low, "file has Linux capabilities"),
			},
			Timeout: suidTimeout,
		}),
}
