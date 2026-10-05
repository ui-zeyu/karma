// package: container instances, package integrity verification (with forensics on
// changed files), auth-chain binary forensics.

package linux

import (
	"fmt"
	"strings"
	"time"

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

// forensicsTail: column 3 of a dpkg -V / rpm -Va output line is the md5 check
// flag, where '5' means the check failed; the files that failed go to the shared
// forensics block.
var forensicsTail = "\nchanged=$(printf '%s\\n' \"$verify\" | awk 'substr($1, 3, 1) == \"5\" {print $NF}')\n" +
	forensicsBlock("changed")

// verifyScript stores the package-verify output in $verify, prints it only when
// non-empty, then gathers forensics in place. The verifier has already run: no
// differences is an empty answer with exit code 0, not a fall-through to another
// package manager. The leading command -v gate keeps that exit 0 from answering
// for a missing package manager: the tier answers 127 instead and the chain
// falls to the other package manager's tier.
func verifyScript(command string) string {
	binary, _, _ := strings.Cut(command, " ")
	head := fmt.Sprintf("command -v %s >/dev/null 2>&1 || exit 127\nverify=$(%s 2>/dev/null)\n[ -n \"$verify\" ] && printf '%%s\\n' \"$verify\"\n",
		binary, command)
	return head + forensicsTail + "exit 0\n"
}

const (
	pkgVerifyDpkg = "dpkg -V" // wrapped by verifyScript, this is the dpkg probe
	pkgVerifyRpm  = "rpm -Va"
)

const pkgVerifyTimeout = 180 * time.Second // a full package verify takes a minute or two on a small VPS, so the timeout is raised here

// pkgHistoryScript: what was installed, upgraded, or removed recently. apt and dpkg
// keep live text logs; the RedHat family answers from its transaction database, so
// both surfaces go into one sectioned script (the empty branch on the other family
// is an empty section the reader drops).
var pkgHistoryScript = script.Lines(
	script.ReadFiles([]string{"/var/log/apt/history.log", "/var/log/dpkg.log"}, `tail -n 300 "$f"`, true),
	`echo "== dnf history"; dnf history 2>/dev/null || yum history 2>/dev/null | head -n 300`,
)

var pkgHistoryRules = []model.Rule{
	model.NewRule("pkg-changed", `^\d{4}-\d{2}-\d{2}\s+\S+\s+(?:install|upgrade|remove|purge|update)\b`,
		model.Low, "package transaction record"),
	model.NewRule("pkg-apt-record", `^(?:Commandline|Install|Upgrade|Remove|Purge):`, model.Low,
		"apt transaction record"),
	model.NewRule("pkg-dnf-record", `^\s*\d+\s+\|`, model.Low, "dnf transaction record"),
	define.KeywordRule,
}

// authBinScript: the programs most often replaced in the login auth chain; once
// pkg-verify points at one, type and mtime close the loop in place.
var authBinScript = `
list=
for f in /usr/sbin/sshd /usr/bin/login /usr/bin/su /usr/bin/sudo /usr/bin/passwd \
         /usr/sbin/unix_chkpwd /sbin/unix_chkpwd \
         /usr/lib*/security/pam_unix.so /lib*/security/pam_unix.so; do
  [ -f "$f" ] && list="$list $f"
done
` + forensicsBlock("list")

var binNotElfRule = model.NewRule("bin-not-elf",
	`(?i)^.*(?:\bscript\b|\b(?:ASCII|Unicode) text\b)`, model.High,
	"script/text where ELF expected").WithExclude(`^/etc/`)

// PackageChecks covers packages.
var PackageChecks = []*model.Check{
	define.LinuxCheck("containers", "Containers (Docker)", model.AspectPackage,
		[]model.Probe{
			{Label: "docker", Inv: model.Dual{Run: nativeDocker, Script: dockerScript}},
		},
		define.CheckOpt{Syntax: "table", Rules: []model.Rule{define.KeywordRule}}),
	define.LinuxCheck("pkg-verify", "Package integrity verification", model.AspectPackage,
		[]model.Probe{
			{Label: "dpkg", Inv: model.Dual{Run: nativePkgVerify([]string{"dpkg", "-V"}), Script: verifyScript(pkgVerifyDpkg)}},
			{Label: "rpm", Inv: model.Dual{Run: nativePkgVerify([]string{"rpm", "-Va"}), Script: verifyScript(pkgVerifyRpm)}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("pkg-checksum", `^..5`, model.High,
					"checksum differs from package db"),
				binNotElfRule,
			},
			// The `== ls` forensics section is ls -l shape; dpkg -V and file lines do not fit
			// and are left as-is
			Syntax:  "ls-l",
			Timeout: pkgVerifyTimeout,
		}),
	define.LinuxCheck("pkg-history", "Recent Package Activity (apt/dpkg/dnf)", model.AspectPackage,
		[]model.Probe{
			{Label: "log", Inv: model.Dual{Run: nativePkgHistory, Script: pkgHistoryScript}},
		},
		define.CheckOpt{Rules: pkgHistoryRules}),
	define.LinuxCheck("auth-binaries", "Auth-chain binaries (type and attributes)", model.AspectPackage,
		[]model.Probe{
			{Label: "file", Inv: model.Dual{Run: nativeAuthBinaries, Script: authBinScript}},
		},
		define.CheckOpt{
			Syntax: "ls-l",
			Rules:  []model.Rule{binNotElfRule, define.KeywordRule},
		}),
}
