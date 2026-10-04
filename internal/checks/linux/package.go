// package: container instances, package integrity verification (with forensics on
// changed files), auth-chain binary forensics.

package linux

import (
	"fmt"
	"time"

	"karma/internal/define"
	"karma/internal/model"
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
// package manager.
func verifyScript(command string) string {
	head := fmt.Sprintf("verify=$(%s 2>/dev/null)\n[ -n \"$verify\" ] && printf '%%s\\n' \"$verify\"\n", command)
	return head + forensicsTail + "exit 0\n"
}

const (
	pkgVerifyDpkg = "dpkg -V" // wrapped by verifyScript, this is the dpkg probe
	pkgVerifyRpm  = "rpm -Va"
)

const pkgVerifyTimeout = 180 * time.Second // a full package verify takes a minute or two on a small VPS, so the timeout is raised here

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
	"file is a script/text (expected ELF binary)").WithExclude(`^/etc/`)

// PackageChecks covers packages.
var PackageChecks = []*model.Check{
	define.LinuxCheck("containers", "Containers (Docker)", model.AspectPackage,
		[]model.Probe{{Label: "docker", Inv: model.Shell{Script: dockerScript}, Requires: []string{"docker"}}},
		define.CheckOpt{Syntax: "table", Rules: []model.Rule{define.KeywordRule}}),
	define.LinuxCheck("pkg-verify", "Package integrity verification", model.AspectPackage,
		[]model.Probe{
			{Label: "dpkg", Inv: model.Shell{Script: verifyScript(pkgVerifyDpkg)}, Requires: []string{"dpkg"}},
			{Label: "rpm", Inv: model.Shell{Script: verifyScript(pkgVerifyRpm)}, Requires: []string{"rpm"}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("pkg-checksum", `^..5`, model.High,
					"file md5 differs from the package database (binary may be replaced)"),
				binNotElfRule,
			},
			// The `== ls` forensics section is ls -l shape; dpkg -V and file lines do not fit
			// and are left as-is
			Syntax:  "ls-l",
			Timeout: pkgVerifyTimeout,
		}),
	define.LinuxCheck("auth-binaries", "Auth-chain binaries (type and attributes)", model.AspectPackage,
		[]model.Probe{{Label: "file", Inv: model.Shell{Script: authBinScript}}},
		define.CheckOpt{
			Syntax: "ls-l",
			Rules:  []model.Rule{binNotElfRule, define.KeywordRule},
		}),
}
