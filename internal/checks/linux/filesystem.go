// filesystem: disks and files: mounts, temp directories, SUID/SGID and content
// signatures under web directories.

package linux

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
)

const suidTimeout = 25 * time.Second

// privFsTypes is the privilege walk's vocabulary: the local storage types, the
// filesystems a setuid/setgid binary can be dropped on. The walk enters each of
// their mounts at its own mount point, because -xdev (which keeps the root pass
// out of /proc, /sys, and every container overlay) prunes by device and so never
// descends into another filesystem. The root filesystem is always walked, whatever
// its type — a container's / is overlay. Network, FUSE, and image filesystems
// stay out: a walk into NFS or a squashfs image is unbounded next to what it can
// find, and a read-only image only carries stock copies.
var privFsTypes = []string{
	"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "zfs",
	"vfat", "msdos", "exfat", "ntfs", "ntfs3", "udf", "tmpfs", "ramfs",
}

// privilegeFind is the setuid/setgid find: one -xdev pass per privilege root,
// so a bit dropped on a data disk or in a tmpfs /tmp is collected too. The root
// list is the kernel's mount table filtered the way native.privilegeRoots does
// it — the root mount first, then one entry per local-storage mount, a device
// named twice walked once — and the mode bit is spelled out with -perm (a bare
// -4000 is not a find expression); the listing itself is one bare path per line.
func privilegeFind(perm string) string { return privilegeFindAt(perm, "/proc/self/mounts") }

// privilegeFindAt is privilegeFind over a given mount table. The tests run the
// pipeline against a fixture, so the awk filter, the per-root loop, and the find
// it feeds are all exercised without a host that can mount a data disk.
func privilegeFindAt(perm, mountsPath string) string {
	return `awk -v types="` + strings.Join(privFsTypes, " ") + `" '
  BEGIN { n = split(types, t, " "); for (i = 1; i <= n; i++) allowed[t[i]] = 1 }
  $2 == "/" { if ($1 ~ /^\/dev\//) seen[$1] = 1; print "/"; next }
  !allowed[$3] { next }
  $1 ~ /^\/dev\// { if (seen[$1]++) next }
  { target = $2; gsub(/\\040/, " ", target); print target }' ` + mountsPath + ` 2>/dev/null |
while IFS= read -r root; do
  find "$root" -xdev -perm ` + perm + ` -type f 2>/dev/null
done`
}

// systemProgramDirs is where a setuid/setgid binary is part of a normal install:
// the bin, sbin, lib, lib64, and libexec trees of /, /usr, and /usr/local. A
// special bit anywhere else (/tmp, /var, /home, /opt, /srv) is a backdoor's
// classic placement, so it lights a rule of its own. Both find listings are one
// bare path per line.
const systemProgramDirs = `^(?:/(?:usr/)?(?:s?bin|lib(?:64|exec)?)/|/usr/local/(?:s?bin|lib(?:64|exec)?)/)`

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

// tmpDirs is the temp-directory word list the temp listing and the miner's name
// walk both cover.
var tmpDirs = []string{"/tmp", "/var/tmp", "/dev/shm"}

// gtfobinsPattern: the list holds basenames only and version suffixes are tolerated
// uniformly after the alternation: python matches python3.x without crossing a
// hyphen to wrongly hit things like python-config.
var gtfobinsPattern = `/(?:[\w.]+/)*(?:` + strings.Join(slices.Sorted(slices.Values(gtfobinsSu)), "|") + `)[0-9.]*$`

// webScriptRoots, webScriptSuffixes, webScriptDepth and webScriptWindow are the
// web-script check's shape; its find command (ssh) and its in-process walk
// (local) are built from them, so the two channels cover identical files. The
// walk crosses devices on purpose: a bind-mounted web root — the usual
// container and compose shape — sits on its own filesystem, and that is exactly
// where the scripts are; depth and the mtime window bound the work.
var (
	webScriptRoots    = []string{"/var/www", "/usr/local/nginx", "/opt"}
	webScriptSuffixes = []string{".php", ".jsp", ".jspx", ".sh", ".py"}
)

const (
	webScriptDepth  = 3
	webScriptWindow = 14 * 24 * time.Hour
	webTimeout      = 15 * time.Second
)

// webScriptFind is that shape as the find command the ssh channel runs.
var webScriptFind = fmt.Sprintf("find %s -maxdepth %d -type f \\( %s \\) -mtime -%d 2>/dev/null",
	strings.Join(webScriptRoots, " "), webScriptDepth, findNameArgs(webScriptSuffixes),
	int(webScriptWindow.Hours()/24))

// findNameArgs renders a find -name alternation for a suffix list: .php becomes
// -name '*.php'.
func findNameArgs(suffixes []string) string {
	args := make([]string, 0, 2*len(suffixes)-1)
	for i, suffix := range suffixes {
		if i > 0 {
			args = append(args, "-o")
		}
		args = append(args, "-name '*"+suffix+"'")
	}
	return strings.Join(args, " ")
}

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

// webshellRoots, webshellFiles and webshellExcludeDirs are the webshell check's
// shape: the directory list (web-dirs' roots plus the common AWD ones), the
// php-family file names, and the directories that only slow the walk. The ssh
// grep and the local walk are built from them and from the three groups above.
var (
	webshellRoots       = []string{"/var/www", "/srv", "/opt", "/app", "/usr/local/nginx", "/usr/share/nginx"}
	webshellFiles       = []string{"*.php", "*.phtml", "*.inc"}
	webshellExcludeDirs = []string{".git", "node_modules"}
)

// webshellRe is the three groups in one alternation — the union the local walk
// collects; the rules grade the groups one by one afterwards.
var webshellRe = regexp.MustCompile(`(?i)(?:` + webshellDirect + `|` + webshellDecode + `|` + webshellCallback + `)`)

// webshellGrep is that shape as the grep -rInEi command the ssh channel runs.
var webshellGrep = "grep -rInEi" +
	" --include='" + strings.Join(webshellFiles, "' --include='") + "'" +
	" --exclude-dir=" + strings.Join(webshellExcludeDirs, " --exclude-dir=") +
	" -e '" + webshellDirect + "' -e '" + webshellDecode + "' -e '" + webshellCallback + "'" +
	" " + strings.Join(webshellRoots, " ") + " 2>/dev/null"

// keyDirs: listing collection runs find -printf (epoch first, body in ls -l shape)
// and clusters locally to mark outlier lines with !/!!; find lists dotfiles
// naturally, so the hidden subsection is dropped.
var keyDirs = []string{"/", "/home", "/opt", "/root", "/srv", "/usr/local"}

// homeTreeRoot, homeTreeDepth and homeTreeArgs are the home-tree check's shape:
// the root, how deep the walk goes, and the flag set tree is called with. The
// ssh find fallback and the local walk take the same root and depth; the flags
// are the tool's own spelling on one side and an argument vector on the other.
// tree is used if present, else 127 falls through to find, whose -printf is
// arranged in ls -l shape for the ls-l pseudo-lexer.
const (
	homeTreeRoot  = "/home"
	homeTreeDepth = 4
	homeTreeArgs  = "-a -p -u -g -s -D --timefmt '%Y-%m-%d %H:%M'"
)

// homeTreeFind is that shape as the find command the ssh fallback runs. tree
// crosses mount points unless -x is given and the check does not pass it, so the
// fallback crosses too.
var homeTreeFind = fmt.Sprintf("LC_ALL=C find %s -maxdepth %d -printf '%s' 2>/dev/null",
	homeTreeRoot, homeTreeDepth, script.LSBodyPrintf)

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
	// Locally df reads /proc/self/mounts and statfs in-process (native_fs).
	define.LinuxCheck("df", "Disk usage", model.AspectFilesystem,
		[]model.Probe{{Label: "df", Inv: model.Dual{Run: native.Df, Script: "df -h"}}},
		define.CheckOpt{Syntax: "df"}),
	define.LinuxCheck("fstab", "Filesystem mount config (fstab)", model.AspectFilesystem,
		readFilesCheck("/etc/fstab"),
		define.CheckOpt{Syntax: "fstab", Rules: []model.Rule{mountRemoteFsRule}}),
	define.LinuxCheck("mounts", "Mount points", model.AspectFilesystem,
		[]model.Probe{
			{Label: "findmnt", Inv: model.Dual{Run: native.Findmnt, Script: "findmnt"}},
			{Label: "mount", Inv: model.Dual{Run: native.Mount, Script: "mount"}},
		},
		define.CheckOpt{
			Filters: []model.LineFilter{
				model.NewFilter("mount-noise", mountNoise, model.FilterDrop),
			},
			Syntax: "table",
			Rules:  []model.Rule{mountRemoteFsRule},
		}),
	// GTFOBins is the only verdict surface on these listings: a documented
	// escalation program under SUID/SGID is critical/high, everything else is
	// quiet evidence (GTFOBins has no separate sgid list, so the suid names
	// stand in). Both listings cover the root filesystem and every local-storage
	// mount — a data disk and a tmpfs /tmp included.
	define.LinuxCheck("suid", "SUID files", model.AspectFilesystem,
		[]model.Probe{
			{Label: "find", Inv: model.Dual{
				Run:    native.ModeBitScan(os.ModeSetuid, privFsTypes),
				Script: privilegeFind("-4000"),
			}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("suid-gtfobins", gtfobinsPattern, model.Critical,
					"SUID privilege-escalation program in GTFOBins"),
				model.NewRule("suid-outside-system", `^/\S+`, model.High,
					"SUID binary outside the system program directories").
					WithExclude(systemProgramDirs),
			},
			Timeout: suidTimeout,
		}),
	define.LinuxCheck("sgid", "SGID files", model.AspectFilesystem,
		[]model.Probe{
			{Label: "find", Inv: model.Dual{
				Run:    native.ModeBitScan(os.ModeSetgid, privFsTypes),
				Script: privilegeFind("-2000"),
			}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("sgid-gtfobins", gtfobinsPattern, model.High,
					"SGID of a GTFOBins privilege-escalation program (group escalation)"),
				model.NewRule("sgid-outside-system", `^/\S+`, model.Medium,
					"SGID binary outside the system program directories").
					WithExclude(systemProgramDirs),
			},
			Timeout: suidTimeout,
		}),
	// Capabilities are another escalation path besides SUID: cap_setuid equals SUID
	define.LinuxCheck("caps", "File capabilities (getcap)", model.AspectFilesystem,
		[]model.Probe{
			// getcap -r / recurses across mounts on its own, so the script tier
			// needs no root list; the local tier walks the same vocabulary.
			{Label: "getcap", Inv: model.Dual{
				Run:    native.FileCaps(privFsTypes),
				Script: "getcap -r / 2>/dev/null",
			}, LineLimit: 200},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				// Both rules span the whole `cap_...=value` assignment: the span is
				// what the panel paints, and getcap's value (e, i, p) carries the
				// meaning.
				model.NewRule("caps-setuid", `cap_setuid[+=][a-z]*`, model.Critical,
					"cap_setuid (SUID-equivalent)"),
				model.NewRule("caps-present", `\bcap_[a-z_]+(?:[+=][a-z]*)?`, model.Low, "file has Linux capabilities"),
			},
			Timeout: suidTimeout,
		}),
	listingCheck("tmp-listing", "Temp directory listing", model.AspectFilesystem, tmpDirs, 200,
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
	listingCheck("key-dirs", "Key directory listing (by mtime)", model.AspectFilesystem,
		keyDirs, 100, []model.Rule{sshMaterialRule, tunnelToolRule, define.KeywordRule}),
	define.LinuxCheck("home-tree", "/home directory tree (four levels deep, including hidden files)", model.AspectFilesystem,
		[]model.Probe{
			{Label: "tree", Inv: model.Dual{
				Run:    native.HomeTree(homeTreeRoot, homeTreeDepth),
				Script: "tree " + homeTreeArgs + " " + homeTreeRoot + " 2>/dev/null",
			}},
			{Label: "find", Inv: model.Dual{Script: homeTreeFind}},
		},
		define.CheckOpt{
			Syntax: "ls-l",
			Rules:  []model.Rule{sshMaterialRule, tunnelToolRule, define.KeywordRule},
		}),
	define.LinuxCheck("web-dirs", "Recently changed scripts in web directories", model.AspectFilesystem,
		[]model.Probe{
			{Label: "find", Inv: model.Dual{
				Run: native.RecentFiles(native.RecentScan{
					Roots:    webScriptRoots,
					Suffixes: webScriptSuffixes,
					MaxDepth: webScriptDepth,
					Window:   webScriptWindow,
				}),
				Script: webScriptFind,
			}, LineLimit: 200},
		},
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
		[]model.Probe{
			{Label: "grep", Inv: model.Dual{
				Run: native.Grep(webshellRoots, native.GrepScan{
					Pattern:     webshellRe,
					Includes:    webshellFiles,
					ExcludeDirs: webshellExcludeDirs,
				}),
				Script: webshellGrep,
			}, LineLimit: 200},
		},
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
}
