// Package define is how the check catalog is built: the default rules and
// filters are merged in here, and the scanner only reads the result. RE2 has
// no lookaround: a negative condition ("not this prefix") is written as the
// rule's line-level Exclude. These rules watch line-per-record output, so the
// exclusion is judged per whole line.
package define

import (
	"slices"

	"karma/internal/model"
)

// PrivateKeyRule is the same on every platform: it joins the global pack on
// Linux, and Windows checks attach it explicitly.
var PrivateKeyRule = model.NewRule(
	"private-key-block",
	`-----BEGIN [A-Z0-9 ]*PRIVATE KEY`,
	model.High,
	"private key block in collected text",
)

// RootkitNames is the program-name list of the public Linux rootkit catalog
// (milabs/awesome-linux-rootkits: the user-mode LD_PRELOAD kits, the LKMs, the
// eBPF and module-less implants, and the related tools it collects) plus the
// tutorial families (h4x, syy) the kallsyms check already carried. It is the
// name half of a signature: a loaded module, a kernel symbol or a .ko/.so file
// that carries one of these names. The alternation is POSIX ERE with plain
// parentheses and no shorthand classes, because the kallsyms check hands the
// same text to the target's own grep.
//
// The bare names are too generic for free text (singularity, umbra, adore and
// rooty are ordinary words), so nothing matches them alone: the file rule needs
// the module/library extension and the module rule needs the name to lead a
// listing row of the module registry.
const RootkitNames = `diamorphine|reptile|rkduck|singularity|caraxes|rooty|krf|suterusu|` +
	`adore|enyelkm|toorkit|randkit|puszek|wukong|liinux|brootus|keysniffer|sutekh|` +
	`lilyofthevalley|subversive|osom|umbra|boopkit|kopycat|triplecross|kovid|` +
	`reveng[_-]rtkit|kprochide|kunkillable|drawbridge|processhider|libzeroevil|` +
	`vlany|beurk|azazel|jynx|umbreon|the[_-]colonel|kernel[_-]?rootkit|lkm[_-]?rootkit|` +
	`arp[_-]?rootkit|heroin`

// KnownRootkitFileRule names the sample's file: an LKM ships as <name>.ko (often
// with a suffix of its own — diamorphine_secret.ko) and a preload kit as
// lib<name>.so. The extension is what keeps the rule spare: a package that
// happens to use one of these words (the Singularity container runtime, say)
// owns no file of that shape. The word boundary is what keeps the span tight —
// a pattern that led with the separator painted the space or slash before the
// name — and it still refuses a name buried inside another word
// (someadore.so is not adore).
var KnownRootkitFileRule = model.NewRule("known-rootkit-file",
	`\b(?:lib)?(?:`+RootkitNames+`)[A-Za-z0-9_.-]*\.(?:ko|so)\b`,
	model.Critical, "module or library file named after a known Linux rootkit")

// KeywordRule is a content-keyword rule; only checks whose surface carries
// human-written content attach it explicitly, and it does not join a global
// pack.
var KeywordRule = model.NewRule(
	"secret-keyword",
	`\b(?:flags?|ctf|secrets?|keys?|passwords?)\b`,
	model.Medium,
	"flag/ctf/secret/key/password keyword",
)

// hiddenExclude is the line-level exclusion shared by the hidden-file rules:
// the system's standard hidden entries on each distribution (socket
// directories such as .X11-unix, display locks, apt's updated, the passwd
// lock, the RedHat family's per-binary build-id tree under /usr/lib, and the
// snapshot and desktop trash directories of /home and the root).
const hiddenExclude = `/+\.(?:(?:X11|ICE|font|XIM|Test)-unix|X[0-9]+-lock|updated|pwd\.lock|build-id|snapshots?|Trash-[0-9]+|DS_Store)`

// rootHiddenExclude is hiddenExclude plus the markers a container and the
// RedHat family write at the filesystem root: .dockerenv, the SELinux relabel
// flag, and the OpenSSL seed file ssh-keygen leaves behind.
const rootHiddenExclude = hiddenExclude + `|(?:^|\s)/\.(?:dockerenv|autorelabel|rnd)\b`

// dashUnitExclude is the one dash-led name a stock system writes into a
// listing: systemd's root mount unit is `-.mount` and its root slice `-.slice`,
// and the generator directories that produce them sit in the unit listings.
const dashUnitExclude = `/-\.(?:mount|slice|target|service|socket|device|swap)$`

// GlobalRules is the cross-check rule pack of the Linux catalog. Rules must be
// written for high precision: for critical / high, spare rather than overreach.
var GlobalRules = []model.Matcher{
	model.NewRule("reverse-shell-dev-tcp", `/dev/(tcp|udp)/[0-9]`, model.Critical,
		"redirect to a network socket (reverse shell trait)"),
	model.NewRule("shell-interactive", `\b(?:ba|z|da|k)?sh\s+-i\b`, model.Critical,
		"interactive shell argument (common reverse shell form)"),
	model.NewRule("netcat-exec", `\bnc(?:1|\.openbsd|\.traditional)?\b[^|\n]*\s-e\b`, model.Critical,
		"netcat -e hands a shell to the network connection"),
	model.NewRule("download-to-shell", `\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b`,
		model.Critical, "downloaded content handed straight to a shell"),
	model.NewRule("base64-decode", `\bbase64\s+(?:--decode|-d|-D)\b`, model.Medium,
		"base64 decode (may hide a payload)"),
	model.NewRule("ld-so-preload", `\bld\.so\.preload\b`, model.Critical,
		"dynamic linker preload configuration"),
	model.NewRule("ld-preload-var", `\bLD_(?:PRELOAD|AUDIT)=`, model.Critical,
		"library preload/audit environment hook"),
	model.NewRule("deleted-binary", `\(deleted\)`, model.Critical, "file deleted but still in use"),
	model.NewRule("known-malware-name",
		`\b(?:xmrig|kdevtmpfsi|kinsing|ddgs|pnscan|masscan|zgrab|spread_qianniu)\b`,
		model.Critical, "known miner/worm sample name"),
	KnownRootkitFileRule,
	model.NewRule("uid0-useradd", `\buseradd\s+[^|\n]*-u\s*0\b`, model.Critical,
		"creating a UID 0 user (backdoor account)"),
	model.NewRule("authorized-keys-write", `>>{1,2}\s*\S*authorized_keys`, model.Critical,
		"writing SSH authorized_keys (persistence)"),
	model.NewRule("account-modify", `\buser(?:add|mod|del)\b`, model.Medium, "account added or modified"),
	model.NewRule("chmod-special-bits", `\bchmod\s+(?:[ug]*[+\-][st]+|[0-7]{4})\b`, model.Medium,
		"chmod sets SUID/SGID or another special bit"),
	PrivateKeyRule,
	// Hidden files (`.foo`): temporary directories are the most common drop
	// point for malicious persistence (HIGH), then /opt /srv /usr/local /etc,
	// the program and library directories, and /home itself (MEDIUM); dotfiles
	// in the user directories below /home are normal and are not marked, which
	// is why /home has to be named separately from /home/*. A rule's span is
	// what the panel paints, so both name the whole path: a pattern that
	// stopped after the first character of the name painted half of it.
	model.NewRule("hidden-tmp-path", `/?(?:(?:var/)?tmp|dev/shm)/\.[A-Za-z0-9_.-]+`, model.High,
		"hidden file in a temporary directory (common persistence spot)").WithExclude(hiddenExclude),
	model.NewRule("hidden-nonhome-path",
		`/?(?:opt|srv|usr/local|etc|bin|sbin|lib|lib64|libexec|home)/\.[A-Za-z0-9_.-]+`, model.Medium,
		"hidden file outside a user home directory").WithExclude(hiddenExclude),
	// A hidden file in the root directory itself — /.root was the SUID copy of
	// nologin in the training case. The name has to end the row: a listing row,
	// a bare-path row and a command's last argument all end with their path,
	// while a request line carries `GET /.env` in the middle, where it is a URL
	// rather than a file on this host. The leading space of a listing row is
	// part of the match, so a bare-path row paints the path alone.
	model.NewRule("hidden-root-path", `(?:^|\s)/\.[A-Za-z0-9_.-]+$`, model.Medium,
		"hidden file in the root directory").WithExclude(rootHiddenExclude),
	// A file whose name begins with a dash: a shell hands it to the next
	// command as an option, which is why `/bin/-t` was what BlackCat's `cat`
	// alias pointed at. The listing rows are bare paths, so the name follows
	// a slash; the temporary-directory grade mirrors the hidden-file pair.
	model.NewRule("odd-dash-tmp", `/(?:tmp|var/tmp|dev/shm)/-[^\s/]+`, model.High,
		"file name starting with a dash in a temporary directory"),
	model.NewRule("odd-dash-name", `/-[^\s/]+`, model.Medium,
		"file name starting with a dash (a shell reads it as an option)").
		WithExclude(dashUnitExclude),
}

// WindowsGlobalRules is the cross-check global rule pack of the Windows
// catalog, merged in by WindowsCheck; currently empty. Linux's GlobalRules
// (reverse shell, ld.so.preload, and similar regexes) target dash text and are
// not applied to Windows output; Windows checks carry all their rules
// themselves.
var WindowsGlobalRules []model.Matcher

// GlobalFilters are the global filters: blank lines are not shown.
var GlobalFilters = []model.LineFilter{
	model.NewFilter("blank", `^[ \t\r]*$`, model.FilterDrop),
}

// globalRules is the platform → default rule pack table: every check carries its
// platform's pack plus its own rules. Windows' pack is empty today (Linux's
// regexes target dash text and are not applied to Windows output), so a Windows
// check carries its own rules alone.
var globalRules = map[model.Platform][]model.Matcher{
	model.Linux:   GlobalRules,
	model.Windows: WindowsGlobalRules,
}

// LinuxCheck builds one Linux check and merges in the Linux global rule pack by
// default. steps is the check's walk: one entry per tier, an entry of several
// probes being a tier that answers as a whole.
func LinuxCheck(id, title string, aspect model.Aspect, steps []model.Step, opt model.Options) *model.Check {
	return build(model.Linux, id, title, aspect, steps, opt)
}

// WindowsCheck builds one Windows check.
func WindowsCheck(id, title string, aspect model.Aspect, steps []model.Step, opt model.Options) *model.Check {
	return build(model.Windows, id, title, aspect, steps, opt)
}

// build is the shared construction path of both platforms: the check's own rules
// first, the platform's default pack after. slices.Concat allocates a new slice
// and never writes through the caller's shared array.
func build(platform model.Platform, id, title string, aspect model.Aspect, steps []model.Step, opt model.Options) *model.Check {
	opt.Filters = slices.Concat(opt.Filters, GlobalFilters)
	opt.Rules = slices.Concat(opt.Rules, globalRules[platform])
	return &model.Check{
		ID:       id,
		Title:    title,
		Aspect:   aspect,
		Platform: platform,
		Steps:    steps,
		Options:  opt,
	}
}
