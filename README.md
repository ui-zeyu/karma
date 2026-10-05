# karma

Semi-automatic incident-response collection: run one command on your analysis host and it reads the target without writing to it. Linux goes over local or SSH; Windows goes over the local channel (system information, accounts, processes, network, persistence, logs, and user behavior). Each check is printed as soon as it finishes, in catalog order. Output is filtered and then highlighted: hit spans are painted by severity and given a reason at the end of the line. No hit, no output.

## Build

```bash
go build -o dist/karma ./cmd/karma
dist/karma --help
```

The version is `0.22.0`; override it with `-ldflags "-X main.version=…"` and print it with `karma version` or `karma --version`.

## Usage

Without a subcommand, karma prints its help. The local channel follows the host platform (`karma local` runs the Windows catalog on Windows and the Linux catalog elsewhere). An SSH target is always treated as Linux.

```bash
dist/karma local                          # local host, every aspect
dist/karma local network process          # aspect names
dist/karma local network,log listen       # commas and spaces are equivalent, check ids mix in
dist/karma local '!pkg-verify'            # a leading ! excludes: everything but that check

dist/karma ssh root@10.0.0.8
dist/karma ssh -p 2222 -i ~/.ssh/id_ed25519 root@10.0.0.8 persistence
dist/karma ssh ssh://root@10.0.0.8:2222
dist/karma ssh -o StrictHostKeyChecking=yes root@10.0.0.8 network,log

dist/karma local mtime /var/www
dist/karma ssh root@10.0.0.8 mtime /var/www /opt

dist/karma local cat /etc/passwd /etc/shadow
dist/karma local ls /tmp /var/tmp
dist/karma local ls                    # the current directory

dist/karma list
dist/karma list network
```

A selector word is a platform name, an aspect name, or a check id; with none given, everything runs. A platform or aspect word counts only if the catalog carries it, so `karma list windows` selects one platform's catalog and `karma list persistence` selects that aspect on both; an unknown word is an error with close matches. A leading `!` on a word excludes instead, with the same vocabulary: `karma local '!pkg-verify'` runs everything but that check and `karma local 'package,!pkg-verify'` runs the aspect without it (quote the word, since shells read `!` too); exclusion wins over inclusion, and words that would leave no checks are an error. The first positional argument of `karma ssh` is the target. The mtime mode is written after that: `mtime DIR...` clusters directory change times (the walk stays on each directory's own filesystem and skips `/proc`, `/sys` and `/dev`); over SSH the connection parameters (-p/-i/-o/--password) are written after the target as usual. The built-in readers are `karma local cat FILE...` and `karma local ls [PATH...]`: cat prints each file's bytes in order, and ls lists each directory — the current one when no path is given, one `== path` section per path when there are several — in the collection's `ls -l` row shape (full paths, newest first, hidden entries included, a file operand prints its own row) with the report's own `ls -l` coloring on a terminal; both read in process rather than through the host's `cat`/`ls`, so a preload hook on those binaries cannot reshape what they print, and an operand that cannot be read is reported after the rest have printed (a failed read exits 1, the status the replaced tool uses).

Linux aspects: `system` `identity` `process` `network` `service` `persistence` `filesystem` `log` `kernel` `package` (74 checks). Windows aspects: `system` `identity` `process` `network` `persistence` `execution` `navigation` `documents` `remote` `log` `timeline` `devices` (42 checks). `karma list` lists both platforms' catalogs as a two-level heading tree — one band per platform, one band per aspect — and every row carries the check id, the title, and the probe chain. Column widths are measured over the whole selection, so the groups line up and a long title wraps inside its own column.

Shared options: `--concurrency` defaults to 6, `--timeout` to 30 seconds, `--max-lines` to 400. With `--save DIR`, every check that collected output writes the target's raw stdout to `<DIR>/<aspect>/<check id>.txt` — the bytes exactly as the channel delivered them, before any reading, filtering, or normalization — one directory per aspect, overwriting same-named files on a repeated run. The directory also carries `manifest.json`: the run's provenance (karma version, channel, host facts, UTC start time) and one entry per file with its size and sha256, so a bundle can be identified and checked for tampering without opening the files.

SSH: `-p` port, `-i` private key (repeatable), `--password` for password authentication (it also unlocks an encrypted private key). The password comes from that flag alone; without it karma uses public keys and exits when authentication fails. An identity that cannot be used (say, a passphrase-protected key with no `--password`) is skipped; that failure surfaces only when nothing is left to authenticate with. `-o` accepts only `StrictHostKeyChecking=no|accept-new|yes`, defaulting to `no`. A failed connection exits 2.

Errors always go to stderr with the `karma: ` prefix and one plain sentence: an unknown command gets close commands (`lst` → `list`), a name mounted elsewhere (`mtime`) gets the way to write it, an unknown flag gets that command's flag list, and a bad value gets one line. Usage and help text is cobra's standard English. Exit codes: 0 for a run that finished and for a mistake the message already explained, 1 when a built-in reader could not read an operand, 2 for a run that could not happen (a failed connection), 130 when interrupted — Ctrl-C stops collection promptly, in-flight checks keep the output they had already read, and the partial report still prints.

## Output

Every bit of the layout is drawn by lipgloss. The report header is one rounded box carrying the host facts and the severity legend. An aspect is a banner filling the line width (dark background, uppercase white text). A check is a left-rail panel: the rail is a half block, carrying the highest hit severity for a signal and grey otherwise; the first line inside the rail is the bold check id with the fallback chain, `filtered N`, and `truncated` on the right, and the body is indented two more columns. Sources (files, commands) are separated into sections by a bold default-color title, with one blank line between sources. Over-long lines are never truncated: lipgloss soft-wraps them, continuation lines share the body indent, and the rail stays unbroken. Nothing is padded with blank space — a line ends where its text ends — and the rows of an `ls -l` listing are lined up column by column (permissions, links, owner, group, size, then the date and the path), the way `ls -l` lays them out, on both channels. The report presents evidence only — a check that was never collected does not appear, exactly like one that was collected with no content. A rendering failure (odd target output hitting a line shape) does not interrupt the run: that check falls back to a thin grey rail with its raw text, and the remaining checks carry on.

| Severity | Presentation |
| --- | --- |
| critical | red thick rail, hit spans bold white on red |
| high | bright red thick rail |
| medium | yellow thick rail |
| low | bright cyan thick rail |

Syntax coloring sits below the hit colors. bash and PowerShell go through chroma; `ls -l`, `env`, `dmesg`, `sshd-config`, `ssh-pubkey`, tables, the `passwd` colon table, listen tables, `ip` addresses and routes, Windows' `netstat -ano` table, `reg query` dumps, and ` | `-segmented rows use built-in line shapes. The `w` uptime banner is muted whole-line instead of being colored by column.

On Windows, redirecting the output to a file with PowerShell 5.1's `>` decodes karma's UTF-8 output with the console code page (GBK on a Chinese system) and re-encodes it, so the file opens as garbage. Use cmd redirection, PowerShell 7, or run `[Console]::OutputEncoding=[Text.Encoding]::UTF8` first; for evidence text, use `--save`, which keeps the bytes intact.

Collection is read-only: it reads files, lists processes, lists sockets, and reads the registry. It never writes to the target, kills processes, or changes the firewall. What you see is what the current login user can see.

## Development

```bash
make fmt vet test                                          # the gates, or each one alone
make race                                                  # the concurrent packages under -race
make staticcheck                                           # when installed
go test ./internal/reader/ -bench . -run XXX               # reading-pipeline benchmark
make dist                                                  # dist/ binaries for both platforms
```

The code lives in `cmd/karma` and `internal/`. Collection, reading, and presentation are separate: `runner` runs the checks, `reader` reads the `== ` sections into a document, and `render` only reads that document. The catalog vocabulary (platform, aspect, check id) is also the selector vocabulary, so what `karma list` shows is what the positional arguments accept.

The reading pass runs every rule against every line, so each rule carries the literals a matching line must contain, derived from its pattern when the catalog is built (`internal/model/prefilter.go`): a line missing all of them never reaches the regexp engine. The derivation is conservative — a pattern whose literal cannot be proven keeps its plain regexp, and a literal of one byte is not worth the scan — and the differential fuzz test holds it to the engine's own verdict. On a twenty-thousand-row listing read against a twelve-rule pack it takes the pass from 180 ms to 7 ms.

A probe tier is normally a host command or a POSIX script; the third kind, `Dual`, carries both a per-channel implementation in one tier: a function karma runs in itself where karma stands on the collected host (`local`), and the POSIX script the target's shell runs over `ssh`. A tier with only one side set exists on that channel alone. Both branches of a tier print the same text shape, so the rules are shared. The Linux catalog is built this way throughout: locally karma reads `/proc`, walks directories, and runs host binaries directly, and the same work travels as the POSIX script over the channel — the hidden-pids check, for instance, is a `kill(pid, 0)` brute force against the `/proc` listing.

The in-process bodies lean on maintained libraries rather than hand-rolled parsers: `/proc` (the process table and its derived columns, mounts, CPU and memory totals, load average) goes through `github.com/prometheus/procfs`, and the socket table, addresses, neighbours, and routes come from `github.com/vishvananda/netlink`'s `sock_diag` and `rtnetlink` dumps. The ELF header in the auth-binaries check is read by the standard library's `debug/elf`. What stays hand-written is what no library takes off our hands: the utmp/wtmp/btmp/lastlog record layout, the `ss`/`ip` text shapes the rules grade, `ls -l` rows, and the `dmesg` ring-buffer read.

Checks that want the same expensive view of the host share one read. The run carries a store (`runstate`) on its context; the first check to ask performs the read and the others read its answer. The SUID, SGID, and file-capability checks are the set this exists for: they want the same traversal of the filesystem with one question different each — one mode bit, or the `security.capability` xattr — so one walk fills all three panels instead of three walks (`find` twice, `getcap` once). That traversal is the root filesystem plus every mount of a local storage type — a tmpfs `/tmp`, an ext4 or XFS data disk — each entered at its own mount point, because `-xdev` prunes by device and would never reach another filesystem from `/`; network, FUSE, and read-only image mounts stay out, and the ssh tier runs the same root list as one `find -xdev` per root. Measured over a 478k-entry tree, a second simultaneous walk pushed a 5.6s traversal to 7.1s and doubled the syscall load the other filesystem checks wait on; on a 2-core VPS the whole catalog run went from 48s to 19s once the three views came from one pass, and the capability panel stopped needing the host's `getcap`. The other directory walks choose per purpose: the web-script recency walk and the miner's temp-name walk cross mount points — a bind-mounted web root, or a service's private tmpfs inside `/tmp`, is exactly where their files live — and are bounded by depth and their mtime window instead; the mtime sweep stays on the filesystem of each directory it is given, so a host that keeps data on several disks is swept with each of them named.

Where a native tier prints the rows a host tool prints, it follows that tool's spelling, because the same rules and lexers read either channel's text: procps for the `ps` table (the STAT modifiers `<`, `N` and `L`, `%MEM` truncated to tenths, an account name cut to seven cells plus `+`) and the uptime banner, coreutils for `df` (sizes rounded up at the printed precision, the use percentage computed over used plus available, the pseudo filesystems its mount filter hides), iproute2 for the socket and neighbour tables (`%ifname` behind a bound address, the NOARP-only neighbours `ip neigh` leaves out, host routes without the `/32`), `lsmod`'s column layout, `dmesg` without the `<N>` ring-buffer prefix, and GNU `find`'s ten-decimal `%T@` timestamp.

Two accounting stores moved in the 26.04 generation. wtmpdb keeps logins in a database while `/var/log/wtmp` stops being written, and lastlog2 does the same for account records. Where the window database is present the `last` tier reports itself unavailable, so the wtmpdb-aware `last(1)` answers with live sessions instead of karma reading a frozen file; where only the lastlog2 database is present the classic `/var/log/lastlog` is the only source left, so the panel says which file it read and that the file stopped being written.

A `Dual` body that cannot answer on the host it runs on reports the tier unavailable, and the local channel then runs that tier's script side through the local shell. That is the same answer the ssh channel gets, and it covers the hosts the in-process bodies cannot serve: a non-Linux developer host, or a Linux host without `/proc`. On a Linux target the in-process body answers and the shell is not involved. A body that fails for any other reason — a refused netlink dump, an unreadable file — reports the failure itself instead of silently falling back, so a real error is not hidden behind the host's own tool.

The local channel is interposition-resistant by construction. Release binaries are statically linked (`CGO_ENABLED=0`, enforced by a guard in `make dist`), so `/etc/ld.so.preload` and `LD_PRELOAD` cannot run code inside karma, and the local tiers read the kernel's own interfaces in-process — `/proc` for the process table (ps, pstree, top) and their derived columns, the utmp/wtmp/btmp/lastlog accounting records for the login views (w, who, last, lastb, lastlog), `/proc/self/mounts` and `statfs(2)` for disks (df, mount, findmnt), `syslog(2)` for the kernel ring buffer (dmesg), `/proc/modules` for lsmod, the `uname(2)` fields for the kernel identity, the `sock_diag` and `rtnetlink` dumps for the socket table (ss), addresses (ip, ifconfig), neighbours (ip neigh, arp), and routes (ip route), the `lstat` and `debug/elf` reads for the auth-binary type and attribute forensics, the `security.capability` xattr for file capabilities, and the raw `/etc/passwd`-style tables for accounts and group membership — getent is deliberately bypassed, because directory service lookups are the interposition surface and the file itself is the evidence. The probes that still ask a host binary are the ones whose data lives behind a daemon or an external tool's own format: the service and container managers, the package managers and their histories, the firewall tables, `lsof`, `capsh`, `tree`, `crontab -l`, and `sudo -n -l`. One probe asks for a host binary on purpose: the hidden-procs comparison runs the host's own `ps` against karma's `/proc` listing, and divergence between the two is itself the finding.
