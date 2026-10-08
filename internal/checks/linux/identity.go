// identity: accounts, login records, sudo grants, PAM config, SSH authorized keys.

package linux

import (
	"fmt"
	"strconv"
	"strings"

	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
)

// sudoersPaths are the surfaces the check covers. The ssh loop prints each
// readable one and exits 0 once anything was read; when nothing is, it exits
// non-zero and the tier falls through to sudo -n -l, which only answers what the
// current user may run.
var sudoersPaths = []string{"/etc/sudoers", "/etc/sudo.conf", "/etc/sudoers.d/*"}

// sudoersListScript is the sh source's list of those paths: the readable ones,
// and a non-zero status when none was — that status is what hands the walk to
// sudo -n -l, which only answers what the current user may run.
var sudoersListScript = `
ok=1
for f in ` + strings.Join(sudoersPaths, " ") + `; do
  [ -f "$f" ] && [ -r "$f" ] || continue
  echo "$f"
  ok=0
done
exit "$ok"
`

// homeGlobs: where user homes live, in the order the walk visits them. A
// trailing "/*" marks a container whose immediate children are homes; a bare
// path is one home itself. native.expandHomes expands it, so this one list is
// the whole vocabulary.
var homeGlobs = []string{"/root", "/home/*"}

// sshdConfigPaths: the sshd config stack. The sshd-config check reads it as
// evidence and the authorized-keys check takes its AuthorizedKeysFile directives
// from the same files, so one list covers both.
var sshdConfigPaths = []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"}

// authorizedKeysDepth bounds the key search under each home directory, the same
// depth the walk of that search passes to find.
const authorizedKeysDepth = 3

// authorizedKeysListScript is the sh source's list of the same stack: the find
// under the homes plus the AuthorizedKeysFile directives of the config, read
// with the target's own tools. Paths named by the directive are listed too: %u
// expands to the user name, %h to the home directory, and a relative path lands
// in that user's home. Default names find already reports are skipped to avoid
// duplicate sections.
//
// Every path it opens is a regular file, tested before the open: the native
// tier of this check reads the same stack through localfs (which reads a planted
// FIFO as empty), and the sh reading would park in open(2) if it opened one —
// the walk's deadline would cut the check and spend its budget on a private
// door.
var authorizedKeysListScript = authorizedKeysListAt(sshdConfigPaths, homeGlobs)

// authorizedKeysListAt is the same list over given surfaces, which is how a
// test drives the whole pipeline — the find under the homes, the config stack,
// the directive expansion — over a fixture.
func authorizedKeysListAt(configPaths, homes []string) string {
	homeWords := strings.Join(homes, " ")
	return `
seen=
pseen=
for d in ` + homeWords + `; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth ` + strconv.Itoa(authorizedKeysDepth) + ` -name 'authorized_keys*' -type f 2>/dev/null | while read -r f; do
    echo "$f"
  done
done
for f in ` + strings.Join(configPaths, " ") + `; do
  [ -f "$f" ] || continue
  awk '$1 == "AuthorizedKeysFile" { for (i = 2; i <= NF; i++) print $i }' "$f" 2>/dev/null
done |
while read -r spec; do
  case " $seen " in *" $spec "*) continue;; esac
  seen="$seen $spec"
  case "$spec" in
    none|authorized_keys|authorized_keys2|.ssh/authorized_keys|.ssh/authorized_keys2) continue;;
  esac
  for d in ` + homeWords + `; do
    [ -d "$d" ] || continue
    p=$(printf '%s\n' "$spec" | sed "s/%u/$(basename "$d")/g")
    p=$(printf '%s\n' "$p" | sed "s|%h|$d|g")
    p=$(printf '%s\n' "$p" | sed "s/%%/%/g")
    case "$p" in /*) ;; *) p="$d/$p";; esac
    case "$p" in */.ssh/authorized_keys|*/.ssh/authorized_keys2) continue;; esac
    case " $pseen " in *" $p "*) continue;; esac
    pseen="$pseen $p"
    [ -f "$p" ] || continue
    echo "$p"
  done
done
`
}

var sshClientConfigPaths = []string{
	"/etc/ssh/ssh_config",
	"/etc/ssh/ssh_config.d/*.conf",
	"/root/.ssh/config",
	"/home/*/.ssh/config",
}

// pamDirs: module directories differ by distro: multiarch (Debian/Ubuntu), lib64
// (RedHat family), flat /usr/lib/security (Alpine etc.). The listing is clustered by
// mtime, so freshly dropped module files surface as outlier lines.
var pamDirs = []string{
	"/etc/pam.d",
	"/usr/lib/*-linux-gnu/security",
	"/usr/lib64/security",
	"/usr/lib/security",
}

// malformedRecordPattern matches a line that is not a record of a
// colon-separated table with the given number of fields: a line holding no
// separator at all, or one carrying more of them than the table has fields.
// Neither shape comes out of the account tools, so the line was written by
// hand — a stray line, an appended field. A comment or an NIS marker (#, +, -)
// starts no record, a line starting with / is a path (a section title is a
// file path), and a blank-first-character line belongs
// to the blank filter.
func malformedRecordPattern(fields int) string {
	return `^\s*[^#/:+\s-][^:\n]*$` + fmt.Sprintf(`|^[^#/\n][^:\n]*(?::[^:\n]*){%d,}$`, fields)
}

// lastRows is how far back the login history reads: `last -n` on the target,
// the same window of the in-process wtmp read.
const lastRows = 200

// IdentityChecks covers identity.
var IdentityChecks = []*model.Check{
	// Raw files only: NSS (getent) is deliberately bypassed — it is the
	// interposition surface, and directory-sourced accounts live on the
	// directory server anyway. The dash-suffixed copy is what user tools
	// leave behind; one that changed while the live file did not is a
	// tamper sign.
	define.LinuxCheck("accounts", "Accounts", model.AspectIdentity,
		readFilesCheck("/etc/passwd", "/etc/passwd-"),
		// passwd/group are colon-separated tables; color fields in a cycle to separate columns
		model.Options{
			Syntax: model.SyntaxColon,
			Filters: []model.LineFilter{
				model.NewFilter("acct-nologin",
					`:(?:/usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false)$`, model.FilterDrop),
			},
			Rules: []model.Matcher{
				model.NewRule("acct-malformed-record", malformedRecordPattern(7), model.High,
					"malformed /etc/passwd record (not seven colon-separated fields)"),
				model.NewRule("acct-root-uid0", `^root:[^:]*:0:`, model.Benign, "the root account itself"),
				// RE2 has no lookahead: "UID 0 that isn't root" becomes an exclusion.
				// Only the UID is tested — a backdoor account can carry any GID.
				model.NewRule("acct-other-uid0", `^[^:\n]+:[^:]*:0:`, model.Critical,
					"non-root account with UID 0").WithExclude(`^root:`),
				model.NewRule("acct-password-field", `^[^:\n]+:.`, model.Medium,
					"password field not x (hash or empty)").WithExclude(`^[^:\n]+:[x*!]`),
				// Unusual accounts with a login shell: by convention system accounts (uid<1000)
				// should not have one (mysql with bash is a persistence signal); human accounts
				// (uid>=1000) and root with a normal shell are expected, so they are not flagged.
				model.NewRule("acct-login-shell",
					`^[^:\n]+:[^:]*:[0-9]{1,3}:[^:]*:[^:]*:[^:]*:/(?:usr/)?bin/(?:ba|z|da|k)?sh$`,
					model.Medium, "system account has a login shell").WithExclude(`^root:`),
			},
		}),
	// Only shadow proves an empty password; locked entries (!*) cannot log in by
	// password, so after filtering the body holds only live hashes and anomalies.
	// An empty root password is its own CRITICAL, matching the uid0 wording.
	define.LinuxCheck("shadow", "Shadow passwords (/etc/shadow)", model.AspectIdentity,
		readFilesCheck("/etc/shadow", "/etc/shadow-"),
		model.Options{
			Syntax: model.SyntaxColon,
			// Ubuntu locks with !*, RedHat with !; only entries whose field 2 is entirely
			// */!/!! are dropped, while !+hash (what passwd -l leaves) is kept.
			Filters: []model.LineFilter{
				model.NewFilter("shadow-locked", `^[^:\n]+:[!*]+:`, model.FilterDrop),
			},
			Rules: []model.Matcher{
				model.NewRule("shadow-malformed-record", malformedRecordPattern(9), model.High,
					"malformed /etc/shadow record (not nine colon-separated fields)"),
				model.NewRule("shadow-empty-root", `^root::`, model.Critical, "empty root password"),
				model.NewRule("shadow-empty", `^[^:\n]+::`, model.High,
					"empty-password account").WithExclude(`^root:`),
				model.NewRule("shadow-md5", `^[^:\n]+:\$1\$`, model.Low, "MD5 password hash (weak algorithm)"),
			},
		}),
	// group and gshadow are read in one pass (gshadow holds the real group passwords,
	// readable only by root); both are colon-separated, so filters and rules are shared.
	// The dash-suffixed copies go along for the same reason as passwd-.
	define.LinuxCheck("groups", "Groups (/etc/group, /etc/gshadow)", model.AspectIdentity,
		readFilesCheck("/etc/group", "/etc/gshadow", "/etc/group-", "/etc/gshadow-"),
		model.Options{
			Syntax: model.SyntaxColon,
			// Only entries with no members and a normal placeholder password (x/*/!/!*) are
			// hidden: an anomalous password field (a real hash is set, letting anyone newgrp
			// into the group) is a signal, and a group with members may be an attacker's
			// foothold regardless of GID.
			Filters: []model.LineFilter{
				model.NewFilter("group-empty", `^[^:\n]+:[!*x]+:[^:]*:$`, model.FilterDrop),
			},
			Rules: []model.Matcher{
				model.NewRule("group-malformed-record", malformedRecordPattern(4), model.High,
					"malformed /etc/group record (not four colon-separated fields)"),
				model.NewRule("group-privileged",
					`^(?:sudo|wheel|admin|staff|root|docker|lxd|disk|shadow|adm):[^:]*:[^:]*:.+`,
					model.Medium, "member of a privileged group"),
				model.NewRule("group-password", `^[^:\n]+:[^:]+:`, model.Medium,
					"group password set (newgrp escalation)").WithExclude(`^[^:\n]+:[*!x]`),
			},
		}),
	// Locally the utmp/wtmp files are parsed in-process (native_utmp); the sh
	// source's tiers are the util-linux binaries over the same files.
	define.LinuxCheck("logins", "Current logins", model.AspectIdentity,
		[]model.Step{
			{{Label: "w", Inv: model.Native{Body: native.W}}},
			{{Label: "who", Inv: model.Native{Body: native.Who}}},
			{{Label: "w-sh", Inv: model.Sh("w")}},
			{{Label: "who-sh", Inv: model.Sh("who")}},
		},
		model.Options{Syntax: model.SyntaxTable}),
	define.LinuxCheck("last", "Login history (last)", model.AspectIdentity,
		[]model.Step{
			{{Label: "last", Inv: model.Native{Body: native.Last(lastRows)}}},
			{{Label: "last-sh", Inv: model.Sh("last -n " + strconv.Itoa(lastRows))}},
		},
		model.Options{Syntax: model.SyntaxLast}),
	define.LinuxCheck("lastlog", "Last account login (lastlog)", model.AspectIdentity,
		[]model.Step{
			{{Label: "lastlog", Inv: model.Native{Body: native.Lastlog}}},
			{{Label: "lastlog-sh", Inv: model.Sh("lastlog")}},
		},
		model.Options{
			// The header is mixed case, so the columns are anchored by their own
			// syntax; the note line ahead of the header stays plain.
			Syntax: model.SyntaxLastlog,
			Filters: []model.LineFilter{
				model.NewFilter("lastlog-never", `Never logged in`, model.FilterDrop),
			},
		}),
	define.LinuxCheck("sudoers", "Sudo grants", model.AspectIdentity,
		[]model.Step{
			{{Label: "cat", Inv: model.FileList{
				List: model.Native{Body: native.SudoersFiles(sudoersPaths)},
				Read: func(path string) model.Invocation { return model.Native{Body: readFile(path, nil)} },
			}}},
			{{Label: "cat-sh", Inv: model.FileList{
				List: model.Sh(sudoersListScript),
				Read: func(path string) model.Invocation { return model.Sh(script.ReadFile(path, `cat "$f"`)) },
			}}},
			{{Label: "sudo", Inv: model.NewCommand("sudo", "-n", "-l")}},
		},
		model.Options{
			Rules: []model.Matcher{
				model.NewRule("sudo-nopasswd", `NOPASSWD`, model.High, "passwordless sudo grant"),
				model.NewRule("sudoers-user-all", `^[^#%\n][^=\n]*\bALL\s*=`, model.Low,
					"sudo grant to non-root user").WithExclude(`^(?:root\s|Defaults\b)`),
				define.KeywordRule,
			},
		}),
	listingCheck("pam", "PAM config and module directories", model.AspectIdentity, pamDirs, 100,
		[]model.Matcher{define.KeywordRule}),
	define.LinuxCheck("authorized-keys", "SSH authorized keys", model.AspectIdentity,
		[]model.Step{
			{{Label: "find", Inv: model.FileList{
				List: model.Native{Body: native.AuthorizedKeyFiles(homeGlobs, authorizedKeysDepth, sshdConfigPaths)},
				Read: func(path string) model.Invocation { return model.Native{Body: readFile(path, nil)} },
			}}},
			{{Label: "find-sh", Inv: model.FileList{
				List: model.Sh(authorizedKeysListScript),
				Read: func(path string) model.Invocation { return model.Sh(script.ReadFile(path, `cat "$f"`)) },
			}}},
		},
		model.Options{
			Syntax: model.SyntaxSSHPubkey,
			Rules: []model.Matcher{
				model.NewRule("authkeys-force-command", `\bcommand="[^"\n]*"`, model.Medium,
					"authorized_keys forced command"),
				define.KeywordRule,
			},
		}),
	// A modified sshd_config (redirected AuthorizedKeysFile, root access opened) is
	// the easiest key-based backdoor
	define.LinuxCheck("sshd-config", "sshd config", model.AspectIdentity,
		readFilesCheck(sshdConfigPaths...),
		model.Options{
			Syntax: model.SyntaxSshdConfig,
			Rules: []model.Matcher{
				model.NewRule("sshd-authorized-keys-file", `^\s*AuthorizedKeysFile\b`, model.Medium,
					"AuthorizedKeysFile overridden"),
				model.NewRule("sshd-permit-root-login", `^\s*PermitRootLogin\s+(?:yes|prohibit-password)\b`,
					model.Low, "root SSH login allowed"),
				model.NewRule("sshd-password-auth", `^\s*PasswordAuthentication\s+yes\b`,
					model.Low, "password login enabled"),
			},
		}),
	// Client-side ProxyCommand/LocalCommand are backdoor vectors too: a login runs the
	// command. The directive form matches sshd_config, so the lexer is the same.
	define.LinuxCheck("ssh-client-config", "SSH client config", model.AspectIdentity,
		readFilesCheck(sshClientConfigPaths...),
		model.Options{
			Syntax: model.SyntaxSshdConfig,
			Rules: []model.Matcher{
				model.NewRule("ssh-client-proxy-command", `^\s*ProxyCommand\b`, model.Medium,
					"ProxyCommand configured"),
				model.NewRule("ssh-client-local-command", `^\s*(?:LocalCommand|PermitLocalCommand)\b`,
					model.Medium, "LocalCommand runs after login"),
			},
		}),
}
