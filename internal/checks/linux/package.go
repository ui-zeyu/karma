// package: container instances, package integrity verification (with forensics on
// changed files), auth-chain binary forensics.

package linux

import (
	"fmt"
	"strings"
	"time"

	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/localfs"
	"karma/internal/model"
	"karma/internal/script"
	"karma/internal/shape"
)

const dockerScript = "docker ps -a 2>/dev/null; echo; docker images 2>/dev/null"

// authBinList is the shell's list of the existing programs among the paths: the
// same list the in-process side expands.
var authBinList = `
list=
for f in ` + strings.Join(authBinPaths, " ") + `; do
  [ -f "$f" ] && list="$list $f"
done
[ -n "$list" ] || exit 0
`

// authBinTypeScript types the listed programs; a host without file(1) answers
// 127, so the surface is simply not there — the same guard the in-process side
// answers with.
var authBinTypeScript = authBinList + `command -v file >/dev/null 2>&1 || exit 127
file $list 2>/dev/null
`

// authBinAttrScript lists the same programs' attributes.
var authBinAttrScript = authBinList + "LC_ALL=C ls -l $list 2>/dev/null\n"

// authBinTier is the check's two forensics surfaces over the same list: the file
// types, then the ls -l attributes, one section each.
func authBinTier() []model.Step {
	return surfacesTier("file", nil, []surface{
		{Title: "file", Native: native.AuthBinTypes(authBinPaths), Script: authBinTypeScript},
		{Title: "ls", Native: native.AuthBinAttrs(authBinPaths), Script: authBinAttrScript},
	})
}

// verifyScript is the sh source's tier for one verifier: the body both sources
// render (script.PkgVerifyScript), which names the files that can be a finding
// and counts the rest per directory. The leading command -v gate keeps a
// missing package manager from answering: the tier answers 127 instead and the
// chain falls to the other package manager's tier.
func verifyScript(command string) string { return script.PkgVerifyScript(command) }

const (
	pkgVerifyDpkg = "dpkg -V" // wrapped by verifyScript, this is the dpkg probe
	pkgVerifyRpm  = "rpm -Va"
)

const pkgVerifyTimeout = 180 * time.Second // a full package verify takes a minute or two on a small VPS, so the timeout is raised here

// unownedDirs are the directories a distribution owns end to end: the program
// and library trees. A file here that no package lists arrived outside the
// package manager — a hand-built install, a vendor agent, or a dropped payload
// (/bin/.lib.so, /usr/lib/inject.so, /bin/-t). /usr/local is left out on
// purpose: it exists for software the administrator builds.
var unownedDirs = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin",
	"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/libexec",
}

const unownedTimeout = 60 * time.Second

// unownedFileRule paints the whole row: the body is bare paths, so the row is
// the file the package database does not carry.
var unownedFileRule = model.NewRule("unowned-file", `^/.*\S$`, model.High,
	"file in a system directory that no package owns")

// pkgHistoryPaths are the text logs the check tails; the RedHat family answers
// from its transaction database instead, so both surfaces go into one sectioned
// script (the empty branch on the other family is an empty section the reader
// drops).
var pkgHistoryPaths = []string{"/var/log/apt/history.log", "/var/log/dpkg.log"}

// pkgHistoryLines is the window both readings take of either surface.
const pkgHistoryLines = 300

// dnfHistoryScript is the sh source's reading of the transaction database: dnf's
// own answer, or yum's head-capped at the same window when dnf is not there.
var dnfHistoryScript = fmt.Sprintf(`dnf history 2>/dev/null || yum history 2>/dev/null | head -n %d`,
	pkgHistoryLines)

// pkgHistoryTier is the check's surfaces in one step: the text logs both families
// write, then the transaction database the RedHat family answers from instead.
func pkgHistoryTier() []model.Step {
	steps := filesTier("log", fmt.Sprintf(`tail -n %d "$f"`, pkgHistoryLines),
		localfs.TailLines(pkgHistoryLines), nil, pkgHistoryPaths)
	steps[0] = append(steps[0], model.Probe{Label: "log", Title: "dnf history",
		Inv: model.Native{Body: native.DnfHistory(pkgHistoryLines)}})
	steps[1] = append(steps[1], model.Probe{Label: "log-sh", Title: "dnf history",
		Inv: model.Sh(dnfHistoryScript)})
	return steps
}

// pkgHistoryRules is what can be a finding in the history: the keyword rule,
// which catches a secret written into a package manager's command line. The
// records themselves — apt's history entries, dpkg's log lines, dnf's table —
// are context rather than findings: the check keeps them with keep filters and
// paints them by shape (the `pkg-history` syntax), so a row carries no severity
// and no reason repeating what the check's own title says.
var pkgHistoryRules = []model.Matcher{
	// The keyword rule is excluded from the package lists apt prints: they are
	// package names, and "debian-keyring" is not a leaked key. A signal there
	// would also drag the whole line — one apt Install record runs to
	// kilobytes — past the history filter.
	define.KeywordRule.WithExclude(`^(?:Install|Upgrade|Remove|Purge):`),
}

// pkgHistoryKeep is the allowlist the history check reads through: apt's own
// package lists are dropped from the panel (one Install line can run to
// kilobytes, and dpkg's log names every package and version that changed), and
// what dpkg logs is narrowed to the transactions themselves rather than the
// unpack/configure/status churn around them. Everything else is counted as
// filtered; the collection's raw text still carries it all. The apt rows the
// check's shaper builds — the start date, then the command line — match the
// first filter's second branch.
var pkgHistoryKeep = []model.LineFilter{
	model.NewFilter("pkg-apt-record",
		`^(?:Start-Date|Commandline):|^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s{2,}\S`, model.FilterKeep),
	// dpkg writes four lines per transaction (install, then configure, then the
	// status churn); the install line's timestamp is the one that matters, so
	// only the verbs that changed which package is on disk are kept.
	model.NewFilter("pkg-dpkg-record",
		`^\d{4}-\d{2}-\d{2} \d\d:\d\d:\d\d (?:install|upgrade|remove|purge) `, model.FilterKeep),
	model.NewFilter("pkg-dnf-record", `^(?:ID\s*\||-{3,}|\s*\d+\s*\|)`, model.FilterKeep),
}

// authBinPaths are the programs most often replaced in the login auth chain;
// once pkg-verify points at one, type and mtime close the loop in place. The
// globs cover both the multiarch and lib64 PAM layouts. The sh loop and the
// local walk cover the same list.
var authBinPaths = []string{
	"/usr/sbin/sshd", "/usr/bin/login", "/usr/bin/su", "/usr/bin/sudo",
	"/usr/bin/passwd", "/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd",
	"/usr/lib*/security/pam_unix.so", "/lib*/security/pam_unix.so",
}

// binNotElfRule is a file whose type is a script or text where an ELF object is
// expected.
var binNotElfRule = model.NewRule("bin-not-elf",
	`(?i)^.*(?:\bscript\b|\b(?:ASCII|Unicode) text\b)`, model.High,
	"script/text where ELF expected").WithExclude(`^/etc/`)

// pkgChangedFileRule covers the verifier's own line, where the file's name sits
// in the clear. dpkg's default format is rpm's: nine flag characters, then the
// attribute field, then the name. A conffile carries 'c' in that field
// ("??5?????? c /etc/hosts", rpm with its own flag letters), and a regular
// package file leaves it blank — three spaces for dpkg, four for rpm — so
// regularFileVerify is the shape of a regular file's mismatch and a conffile row
// can never match it. A changed conffile is the administrator's edit; a regular
// package file that no longer matches the package db is the finding, and the
// whole record is painted rather than the three flag characters pkg-checksum
// marks. The flag position is the md5 slot in both verifiers (dpkg: result[2] =
// checks->md5sum; rpm: the third of SM5DLUGTP).
const regularFileVerify = `^..5\S{6}\s{2,}/`

var pkgChangedFileRule = model.NewRule("pkg-changed-file",
	regularFileVerify+`.*$`, model.Medium, "package file (not a conffile) differs from the package db")

// The two forensics sections list exactly the files the verifier flagged, so a
// row there is a changed file by construction — and among them the binary is the
// finding: a row for an ELF object is a replaced binary or library, and one
// carrying an execute bit is a replaced program. Neither may pass for an ordinary
// listing row, so both paint the whole record rather than one field, and the reason
// says which file changed. A conffile row (no execute bit, text type) stays quiet:
// those are the administrator's edits, and marking them would drown the binary in
// them.
//
// The span is the whole row, so the hit covers the metadata the ls-l lexer would
// otherwise color; the rules are for pkg-verify alone, because its ls section is
// the changed-file list — auth-binaries lists every auth binary, changed or not.
var (
	// file(1) pads its type column when it reads many names at once, so the
	// separator is ": " with any run of spaces after it — the local channel's
	// in-process rows use a single space.
	pkgChangedELFRule = model.NewRule("pkg-changed-elf",
		`^/\S+:\s+ELF.*$`, model.Critical, "ELF binary or library changed since install")
	pkgChangedExecRule = model.NewRule("pkg-changed-exec",
		`^(?:-[r-][w-][xsS].*|-...[r-][w-][xsS].*|-......[r-][w-][xsS].*)$`, model.Critical,
		"executable changed since install")
)

// PackageChecks covers packages.
var PackageChecks = []*model.Check{
	define.LinuxCheck("containers", "Containers (Docker)", model.AspectPackage,
		[]model.Step{
			{{Label: "docker", Inv: model.Native{Body: native.Docker}}},
			{{Label: "docker-sh", Inv: model.Sh(dockerScript)}},
		},
		define.CheckOpt{Syntax: model.SyntaxTable, Rules: []model.Matcher{define.KeywordRule}}),
	define.LinuxCheck("pkg-verify", "Package integrity verification", model.AspectPackage,
		[]model.Step{
			{{Label: "dpkg", Inv: model.Native{Body: native.PkgVerify([]string{"dpkg", "-V"})}}},
			{{Label: "dpkg-sh", Inv: model.Sh(verifyScript(pkgVerifyDpkg))}},
			{{Label: "rpm", Inv: model.Native{Body: native.PkgVerify([]string{"rpm", "-Va"})}}},
			{{Label: "rpm-sh", Inv: model.Sh(verifyScript(pkgVerifyRpm))}},
		},
		define.CheckOpt{
			Rules: []model.Matcher{
				pkgChangedFileRule,
				model.NewRule("pkg-checksum", `^..5`, model.High,
					"checksum differs from package db").WithExclude(regularFileVerify),
				binNotElfRule,
				pkgChangedELFRule,
				pkgChangedExecRule,
			},
			// The `== ls` forensics section is ls -l shape; dpkg -V and file lines do not fit
			// and are left as-is
			Syntax:  model.SyntaxLsL,
			Timeout: pkgVerifyTimeout,
		}),
	define.LinuxCheck("unowned-files", "Files no package owns (system directories)", model.AspectPackage,
		[]model.Step{
			{{Label: "find", Inv: model.Native{Body: native.UnownedFiles(unownedDirs)}, Cap: model.Scan(openScanLines)}},
			{{Label: "find-sh", Inv: model.Sh(script.UnownedScript(unownedDirs)), Cap: model.Scan(openScanLines)}},
		},
		define.CheckOpt{Rules: []model.Matcher{unownedFileRule}, Timeout: unownedTimeout}),
	define.LinuxCheck("pkg-history", "Recent Package Activity (apt/dpkg/dnf)", model.AspectPackage,
		pkgHistoryTier(),
		define.CheckOpt{
			Rules:     pkgHistoryRules,
			Filters:   pkgHistoryKeep,
			Syntax:    model.SyntaxPkgHistory,
			Normalize: shape.AptHistory,
		}),
	define.LinuxCheck("auth-binaries", "Auth-chain binaries (type and attributes)", model.AspectPackage,
		authBinTier(),
		define.CheckOpt{
			Syntax: model.SyntaxLsL,
			Rules:  []model.Matcher{binNotElfRule, define.KeywordRule},
		}),
}
