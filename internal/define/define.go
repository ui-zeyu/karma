// Package define is how the check catalog is built: the default rules and
// filters are merged in here, and the scanner only reads the result. RE2 has
// no lookaround: a negative condition ("not this prefix") is written as the
// rule's line-level Exclude. These rules watch line-per-record output, so the
// exclusion is judged per whole line.
package define

import (
	"slices"
	"time"

	"karma/internal/model"
)

// CheckOpt is the optional surface of a check: rules, filters, body
// normalization, presentation, and run parameters. The zero value is usable
// (no own rules, no normalization, the global timeout and read cap).
type CheckOpt struct {
	Filters       []model.LineFilter
	Rules         []model.Rule
	Normalize     model.Normalizer
	Syntax        string
	SectionSyntax []model.SectionSyntax
	Timeout       time.Duration
	ScanBytes     int
}

// PrivateKeyRule is the same on every platform: it joins the global pack on
// Linux, and Windows checks attach it explicitly.
var PrivateKeyRule = model.NewRule(
	"private-key-block",
	`-----BEGIN [A-Z0-9 ]*PRIVATE KEY`,
	model.High,
	"private key block in collected text",
)

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
// lock).
const hiddenExclude = `/+\.(?:(?:X11|ICE|font|XIM|Test)-unix|X[0-9]+-lock|updated|pwd\.lock)`

// GlobalRules is the cross-check rule pack of the Linux catalog. Rules must be
// written for high precision: for critical / high, spare rather than overreach.
var GlobalRules = []model.Rule{
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
	model.NewRule("uid0-useradd", `\buseradd\s+[^|\n]*-u\s*0\b`, model.Critical,
		"creating a UID 0 user (backdoor account)"),
	model.NewRule("authorized-keys-write", `>>{1,2}\s*\S*authorized_keys`, model.Critical,
		"writing SSH authorized_keys (persistence)"),
	model.NewRule("account-modify", `\buser(?:add|mod|del)\b`, model.Medium, "account added or modified"),
	model.NewRule("chmod-special-bits", `\bchmod\s+(?:[ug]*[+\-][st]+|[0-7]{4})\b`, model.Medium,
		"chmod sets SUID/SGID or another special bit"),
	PrivateKeyRule,
	// Hidden files (`.foo`): temporary directories are the most common drop
	// point for malicious persistence (HIGH), then /opt /srv /usr/local /etc
	// (MEDIUM); dotfiles in home directories are normal and are not marked.
	// A rule's span is what the panel paints, so both name the whole path: a
	// pattern that stopped after the first character of the name painted half
	// of it.
	model.NewRule("hidden-tmp-path", `/?(?:(?:var/)?tmp|dev/shm)/\.[A-Za-z0-9_.-]+`, model.High,
		"hidden file in a temporary directory (common persistence spot)").WithExclude(hiddenExclude),
	model.NewRule("hidden-nonhome-path", `/?(?:opt|srv|usr/local|etc)/\.[A-Za-z0-9_.-]+`, model.Medium,
		"hidden file outside a home directory").WithExclude(hiddenExclude),
}

// WindowsGlobalRules is the cross-check global rule pack of the Windows
// catalog, merged in by WindowsCheck; currently empty. Linux's GlobalRules
// (reverse shell, ld.so.preload, and similar regexes) target dash text and are
// not applied to Windows output; Windows checks carry all their rules
// themselves.
var WindowsGlobalRules []model.Rule

// GlobalFilters are the global filters: blank lines are not shown.
var GlobalFilters = []model.LineFilter{
	model.NewFilter("blank", `^[ \t\r]*$`, model.FilterDrop),
}

// globalRules is the platform → default rule pack table: every check carries its
// platform's pack plus its own rules. Windows' pack is empty today (Linux's
// regexes target dash text and are not applied to Windows output), so a Windows
// check carries its own rules alone.
var globalRules = map[model.Platform][]model.Rule{
	model.Linux:   GlobalRules,
	model.Windows: WindowsGlobalRules,
}

// LinuxCheck builds one Linux check and merges in the Linux global rule pack by
// default.
func LinuxCheck(id, title string, aspect model.Aspect, probes []model.Probe, opt CheckOpt) *model.Check {
	return build(model.Linux, id, title, aspect, probes, opt)
}

// WindowsCheck builds one Windows check.
func WindowsCheck(id, title string, aspect model.Aspect, probes []model.Probe, opt CheckOpt) *model.Check {
	return build(model.Windows, id, title, aspect, probes, opt)
}

// build is the shared construction path of both platforms: the check's own rules
// first, the platform's default pack after. slices.Concat allocates a new slice
// and never writes through the caller's shared array.
func build(platform model.Platform, id, title string, aspect model.Aspect, probes []model.Probe, opt CheckOpt) *model.Check {
	return &model.Check{
		ID:            id,
		Title:         title,
		Aspect:        aspect,
		Platform:      platform,
		Probes:        probes,
		Filters:       slices.Concat(opt.Filters, GlobalFilters),
		Rules:         slices.Concat(opt.Rules, globalRules[platform]),
		Timeout:       opt.Timeout,
		Syntax:        opt.Syntax,
		SectionSyntax: opt.SectionSyntax,
		Normalize:     opt.Normalize,
		ScanBytes:     opt.ScanBytes,
	}
}
