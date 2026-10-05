// identity: accounts, login records, sudo grants, PAM config, SSH authorized keys.

package linux

import (
	"karma/internal/define"
	"karma/internal/model"
)

// sudoers: stop as soon as a file is readable; if none is, exit non-zero and fall
// through to sudo -n -l, which only answers what the current user may run.
const sudoersScript = `
ok=1
for f in /etc/sudoers /etc/sudo.conf /etc/sudoers.d/*; do
  [ -f "$f" ] && [ -r "$f" ] || continue
  echo "== $f"
  cat "$f"
  ok=0
done
exit "$ok"
`

// authorizedKeysScript finds each user's authorized_keys; paths named by the
// AuthorizedKeysFile directive are read too: %u expands to the user name, %h to
// the home directory, and a relative path lands in that user's home. Default names
// find already reports are skipped to avoid duplicate sections.
const authorizedKeysScript = `
seen=
pseen=
for d in /root /home/*; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 3 -name 'authorized_keys*' -type f 2>/dev/null | while read -r f; do
    echo "== $f"
    cat "$f" 2>/dev/null
  done
done
awk '$1 == "AuthorizedKeysFile" { for (i = 2; i <= NF; i++) print $i }' \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null |
while read -r spec; do
  case " $seen " in *" $spec "*) continue;; esac
  seen="$seen $spec"
  case "$spec" in
    none|authorized_keys|authorized_keys2|.ssh/authorized_keys|.ssh/authorized_keys2) continue;;
  esac
  for d in /root /home/*; do
    [ -d "$d" ] || continue
    p=$(printf '%s\n' "$spec" | sed "s/%u/$(basename "$d")/g")
    p=$(printf '%s\n' "$p" | sed "s|%h|$d|g")
    p=$(printf '%s\n' "$p" | sed "s/%%/%/g")
    case "$p" in /*) ;; *) p="$d/$p";; esac
    case "$p" in */.ssh/authorized_keys|*/.ssh/authorized_keys2) continue;; esac
    case " $pseen " in *" $p "*) continue;; esac
    pseen="$pseen $p"
    [ -f "$p" ] || continue
    echo "== $p"
    cat "$p" 2>/dev/null
  done
done
`

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
		define.CheckOpt{
			Syntax: "colon",
			Filters: []model.LineFilter{
				model.NewFilter("acct-nologin",
					`:(?:/usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false)$`, model.FilterDrop),
			},
			Rules: []model.Rule{
				model.NewRule("acct-root-uid0", `^root:[^:]*:0:0:`, model.Benign, "the root account itself"),
				// RE2 has no lookahead: "UID 0 that isn't root" becomes an exclusion
				model.NewRule("acct-other-uid0", `^[^:\n]+:[^:]*:0:0:`, model.Critical,
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
		define.CheckOpt{
			Syntax: "colon",
			// Ubuntu locks with !*, RedHat with !; only entries whose field 2 is entirely
			// */!/!! are dropped, while !+hash (what passwd -l leaves) is kept.
			Filters: []model.LineFilter{
				model.NewFilter("shadow-locked", `^[^:\n]+:[!*]+:`, model.FilterDrop),
			},
			Rules: []model.Rule{
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
		define.CheckOpt{
			Syntax: "colon",
			// Only entries with no members and a normal placeholder password (x/*/!/!*) are
			// hidden: an anomalous password field (a real hash is set, letting anyone newgrp
			// into the group) is a signal, and a group with members may be an attacker's
			// foothold regardless of GID.
			Filters: []model.LineFilter{
				model.NewFilter("group-empty", `^[^:\n]+:[!*x]+:[^:]*:$`, model.FilterDrop),
			},
			Rules: []model.Rule{
				model.NewRule("group-privileged",
					`^(?:sudo|wheel|admin|staff|root|docker|lxd|disk|shadow|adm):[^:]*:[^:]*:.+`,
					model.Medium, "member of a privileged group"),
				model.NewRule("group-password", `^[^:\n]+:[^:]+:`, model.Medium,
					"group password set (newgrp escalation)").WithExclude(`^[^:\n]+:[*!x]`),
			},
		}),
	// Locally the utmp/wtmp files are parsed in-process (native_utmp); on ssh
	// the same labels run the util-linux binaries.
	define.LinuxCheck("logins", "Current logins", model.AspectIdentity,
		[]model.Probe{
			{Label: "w", Inv: model.Dual{Run: nativeW, Script: "w"}},
			{Label: "who", Inv: model.Dual{Run: nativeWho, Script: "who"}},
		},
		define.CheckOpt{Syntax: "table"}),
	define.LinuxCheck("last", "Login history (last)", model.AspectIdentity,
		[]model.Probe{{Label: "last", Inv: model.Dual{Run: nativeLast, Script: "last -n 200"}}},
		define.CheckOpt{Syntax: "table"}),
	define.LinuxCheck("lastlog", "Last account login (lastlog)", model.AspectIdentity,
		[]model.Probe{{Label: "lastlog", Inv: model.Dual{Run: nativeLastlog, Script: "lastlog"}}},
		define.CheckOpt{
			// The header is mixed case, so the columns are anchored by their own
			// syntax; the note line ahead of the header stays plain.
			Syntax: "lastlog",
			Filters: []model.LineFilter{
				model.NewFilter("lastlog-never", `Never logged in`, model.FilterDrop),
			},
		}),
	define.LinuxCheck("sudoers", "Sudo grants", model.AspectIdentity,
		[]model.Probe{
			{Label: "cat", Inv: model.Dual{Run: nativeSudoers, Script: sudoersScript}},
			{Label: "sudo", Inv: model.NewCommand("sudo", "-n", "-l")},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("sudo-nopasswd", `NOPASSWD`, model.High, "passwordless sudo grant"),
				model.NewRule("sudoers-user-all", `^[^#%\n][^=\n]*\bALL\s*=`, model.Low,
					"sudo grant to non-root user").WithExclude(`^(?:root\s|Defaults\b)`),
				define.KeywordRule,
			},
		}),
	listingCheck("pam", "PAM config and module directories", model.AspectIdentity, pamDirs, 100,
		[]model.Rule{define.KeywordRule}),
	define.LinuxCheck("authorized-keys", "SSH authorized keys", model.AspectIdentity,
		[]model.Probe{
			{Label: "find", Inv: model.Dual{Run: nativeAuthorizedKeys, Script: authorizedKeysScript}},
		},
		define.CheckOpt{
			Syntax: "ssh-pubkey",
			Rules: []model.Rule{
				model.NewRule("authkeys-force-command", `\bcommand="[^"\n]*"`, model.Medium,
					"authorized_keys forced command"),
				define.KeywordRule,
			},
		}),
	// A modified sshd_config (redirected AuthorizedKeysFile, root access opened) is
	// the easiest key-based backdoor
	define.LinuxCheck("sshd-config", "sshd config", model.AspectIdentity,
		readFilesCheck("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"),
		define.CheckOpt{
			Syntax: "sshd-config",
			Rules: []model.Rule{
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
		define.CheckOpt{
			Syntax: "sshd-config",
			Rules: []model.Rule{
				model.NewRule("ssh-client-proxy-command", `^\s*ProxyCommand\b`, model.Medium,
					"ProxyCommand configured"),
				model.NewRule("ssh-client-local-command", `^\s*(?:LocalCommand|PermitLocalCommand)\b`,
					model.Medium, "LocalCommand runs after login"),
			},
		}),
}
