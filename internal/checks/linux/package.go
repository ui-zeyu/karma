// package: container instances, package integrity verification (with forensics on
// changed files), auth-chain binary forensics.

package linux

import (
	"fmt"
	"strings"
	"time"

	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
)

const dockerScript = "docker ps -a 2>/dev/null; echo; docker images 2>/dev/null"

// forensicsBlock gathers in-place forensics for one file list: file (type) and
// ls -l (attributes and mtime) for the files the shell variable names.
func forensicsBlock(variable string) string {
	return fmt.Sprintf(`
if [ -n "$%[1]s" ]; then
  if command -v file >/dev/null 2>&1; then
    echo "== file"
    file $%[1]s 2>/dev/null
  fi
  echo "== ls"
  LC_ALL=C ls -l $%[1]s 2>/dev/null
fi
`, variable)
}

// verifyScript is the ssh and ttyd tier for one verifier: the body both
// channels render (script.PkgVerifyScript), which names the files that can be a
// finding and counts the rest per directory. The verifier has already run: no
// differences is an empty answer with exit code 0, not a fall-through to
// another package manager. The leading command -v gate keeps that exit 0 from
// answering for a missing package manager: the tier answers 127 instead and the
// chain falls to the other package manager's tier.
func verifyScript(command string) string { return script.PkgVerifyScript(command) }

const (
	pkgVerifyDpkg = "dpkg -V" // wrapped by verifyScript, this is the dpkg probe
	pkgVerifyRpm  = "rpm -Va"
)

const pkgVerifyTimeout = 180 * time.Second // a full package verify takes a minute or two on a small VPS, so the timeout is raised here

// pkgHistoryScript: what was installed, upgraded, or removed recently. apt and dpkg
// keep live text logs; the RedHat family answers from its transaction database, so
// both surfaces go into one sectioned script (the empty branch on the other family
// is an empty section the reader drops).
// pkgHistoryPaths are the text logs the check tails; the RedHat family answers
// from its transaction database instead.
var pkgHistoryPaths = []string{"/var/log/apt/history.log", "/var/log/dpkg.log"}

var pkgHistoryScript = script.Lines(
	script.ReadFiles(pkgHistoryPaths, `tail -n 300 "$f"`, true),
	`echo "== dnf history"; dnf history 2>/dev/null || yum history 2>/dev/null | head -n 300`,
)

// pkgHistoryRules is what can be a finding in the history: the keyword rule,
// which catches a secret written into a package manager's command line. The
// records themselves — apt's history entries, dpkg's log lines, dnf's table —
// are context rather than findings: the check keeps them with keep filters and
// paints them by shape (the `pkg-history` syntax), so a row carries no severity
// and no reason repeating what the check's own title says.
var pkgHistoryRules = []model.Rule{
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
// filtered; the raw text --save writes still carries it all.
var pkgHistoryKeep = []model.LineFilter{
	model.NewFilter("pkg-apt-record", `^(?:Start-Date|Commandline):`, model.FilterKeep),
	// dpkg writes four lines per transaction (install, then configure, then the
	// status churn); the install line's timestamp is the one that matters, so
	// only the verbs that changed which package is on disk are kept.
	model.NewFilter("pkg-dpkg-record",
		`^\d{4}-\d{2}-\d{2} \d\d:\d\d:\d\d (?:install|upgrade|remove|purge) `, model.FilterKeep),
	model.NewFilter("pkg-dnf-record", `^(?:ID\s*\||-{3,}|\s*\d+\s*\|)`, model.FilterKeep),
}

// authBinPaths are the programs most often replaced in the login auth chain;
// once pkg-verify points at one, type and mtime close the loop in place. The
// globs cover both the multiarch and lib64 PAM layouts. The ssh loop and the
// local walk cover the same list.
var authBinPaths = []string{
	"/usr/sbin/sshd", "/usr/bin/login", "/usr/bin/su", "/usr/bin/sudo",
	"/usr/bin/passwd", "/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd",
	"/usr/lib*/security/pam_unix.so", "/lib*/security/pam_unix.so",
}

var authBinScript = `
list=
for f in ` + strings.Join(authBinPaths, " ") + `; do
  [ -f "$f" ] && list="$list $f"
done
` + forensicsBlock("list")

var binNotElfRule = model.NewRule("bin-not-elf",
	`(?i)^.*(?:\bscript\b|\b(?:ASCII|Unicode) text\b)`, model.High,
	"script/text where ELF expected").WithExclude(`^/etc/`)

// pkgChangedFileRule covers the verifier's own line, where the file's name sits
// in the clear. dpkg's default format is rpm's: nine flag characters, then the
// attribute field, then the name. A conffile carries 'c' in that field
// ("??5?????? c /etc/hosts", rpm with its own flag letters), and a regular
// package file leaves it blank — three spaces for dpkg, two for rpm — so a
// mismatch on a conffile can never match here. A changed conffile is the
// administrator's edit; a regular package file that no longer matches the
// package db is the finding, and the whole record is painted rather than the
// three flag characters pkg-checksum marks. The flag position is the md5 slot in
// both verifiers (dpkg: result[2] = checks->md5sum; rpm: the third of SM5DLUGTP).
var pkgChangedFileRule = model.NewRule("pkg-changed-file",
	`^..5\S{6}\s{2,}/.*$`, model.High, "package file (not a conffile) differs from the package db")

// The two forensics sections list exactly the files the verifier flagged, so a
// row there is a changed file by construction — and among them the binary is the
// finding: a row for an ELF object is a replaced binary or library, and one
// carrying an execute bit is a replaced program. Neither may pass for an
// ordinary listing row, so both paint the whole record rather than one field,
// and the reason says which file changed. A conffile row (no execute bit, text
// type) stays quiet: those are the administrator's edits, and marking them would
// drown the binary in them.
//
// The span is the whole row, so the hit covers the metadata the ls-l lexer would
// otherwise color; the rules are for pkg-verify alone, because its ls section is
// the changed-file list — auth-binaries lists every auth binary, changed or not.
var (
	// file(1) pads its type column when it reads many names at once, so the
	// separator is ": " with any run of spaces after it — the local channel's
	// in-process rows use a single space.
	pkgChangedELFRule = model.NewRule("pkg-changed-elf",
		`^/\S+:\s+ELF.*$`, model.High, "ELF binary or library changed since install")
	pkgChangedExecRule = model.NewRule("pkg-changed-exec",
		`^(?:-[r-][w-][xsS].*|-...[r-][w-][xsS].*|-......[r-][w-][xsS].*)$`, model.High,
		"executable changed since install")
)

// PackageChecks covers packages.
var PackageChecks = []*model.Check{
	define.LinuxCheck("containers", "Containers (Docker)", model.AspectPackage,
		[]model.Probe{
			{Label: "docker", Inv: model.Dual{Run: native.Docker, Script: dockerScript}},
		},
		define.CheckOpt{Syntax: "table", Rules: []model.Rule{define.KeywordRule}}),
	define.LinuxCheck("pkg-verify", "Package integrity verification", model.AspectPackage,
		[]model.Probe{
			{Label: "dpkg", Inv: model.Dual{Run: native.PkgVerify([]string{"dpkg", "-V"}), Script: verifyScript(pkgVerifyDpkg)}},
			{Label: "rpm", Inv: model.Dual{Run: native.PkgVerify([]string{"rpm", "-Va"}), Script: verifyScript(pkgVerifyRpm)}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				// The whole-record rule comes first: both it and pkg-checksum
				// match a regular package file's mismatch at the same severity,
				// and the row's reason is the first of the top severity, so the
				// order makes the row say which case it is. The conffile rows
				// match pkg-checksum alone and keep its three-character span.
				pkgChangedFileRule,
				model.NewRule("pkg-checksum", `^..5`, model.High,
					"checksum differs from package db"),
				binNotElfRule,
				pkgChangedELFRule,
				pkgChangedExecRule,
			},
			// The `== ls` forensics section is ls -l shape; dpkg -V and file lines do not fit
			// and are left as-is
			Syntax:  "ls-l",
			Timeout: pkgVerifyTimeout,
		}),
	define.LinuxCheck("pkg-history", "Recent Package Activity (apt/dpkg/dnf)", model.AspectPackage,
		[]model.Probe{
			{Label: "log", Inv: model.Dual{Run: native.PkgHistory(pkgHistoryPaths), Script: pkgHistoryScript}},
		},
		define.CheckOpt{Rules: pkgHistoryRules, Filters: pkgHistoryKeep, Syntax: "pkg-history"}),
	define.LinuxCheck("auth-binaries", "Auth-chain binaries (type and attributes)", model.AspectPackage,
		[]model.Probe{
			{Label: "file", Inv: model.Dual{Run: native.AuthBinaries(authBinPaths), Script: authBinScript}},
		},
		define.CheckOpt{
			Syntax: "ls-l",
			Rules:  []model.Rule{binNotElfRule, define.KeywordRule},
		}),
}
