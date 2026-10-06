# karma

Semi-automatic incident-response collection. Run one command on your analysis host and karma reads
the target without writing to it: Linux over the local channel, SSH, or a ttyd web terminal, and
Windows over the local channel. Each check prints as soon as it finishes, in catalog order, and the
output is filtered before it is shown — hits are highlighted and given a reason at the end of the
line. No hit, no output.

## Build

```bash
go build -o dist/karma ./cmd/karma     # this host
make dist                              # dist/ binaries for linux/amd64, linux/arm64, windows/amd64 and this host
```

The version is `0.36.0`. Override it with `-ldflags "-X main.version=…"`; `karma version` prints it.

## Usage

| Channel | Command |
| --- | --- |
| This host | `karma local [selector...]` |
| SSH target | `karma ssh [flags] TARGET [selector...]` |
| ttyd web terminal | `karma ttyd [flags] TARGET [selector...]` |

```bash
dist/karma local                          # every aspect
dist/karma local network process          # aspect names
dist/karma local network,log listen       # commas and spaces are equivalent; check ids mix in
dist/karma local '!pkg-verify'            # a leading ! excludes those checks

dist/karma ssh root@10.0.0.8 network
dist/karma ssh -p 2222 -i ~/.ssh/id_ed25519 root@10.0.0.8 persistence
dist/karma ssh root@10.0.0.8 'package,!pkg-verify'

dist/karma ttyd ws://10.0.0.8:7681        # a bare host means port 7681
dist/karma ttyd ws://user:pass@10.0.0.8:80 network
dist/karma ttyd wss://10.0.0.8:7681 --tls-pin <sha256-hex>

dist/karma list                           # the catalog: every platform, aspect, check id and probe chain
```

A selector word is a platform name, an aspect name, or a check id; with none given, everything runs.
An unknown word is an error with close matches. `!` excludes, and exclusion wins over inclusion. The
first positional argument of `ssh` and `ttyd` is the target; connection flags (`-p`, `-i`,
`--password`, `-o`, `--credential`, `--tls-pin`) follow the target as usual.

A ttyd target must accept input: ttyd 1.7.4 and later need `-W/--writable`, earlier releases are
writable by default. karma connects to the same endpoint as a second client, so it never disturbs the
console the operator is looking at. SSH accepts `[user@]host`, `ssh://[user@]host[:port]`, `-p` port,
`-i` private key (repeatable), `--password` (also the passphrase of an encrypted key) and
`-o StrictHostKeyChecking=no|accept-new|yes`.

**A remote collection runs through a collector.** `ssh` and `ttyd` place this binary on the target,
keep it there, and collect through it: every tier then runs in process on the target, so a remote
report is the one a local run on that host would have drawn — the shell is not in the path, and the
kernel is read directly. The copy is reused on later runs and is proved before it is executed (its
md5 equals the build's, and a copy that does not match is replaced rather than run). It is looked for
in the account's own directory first (`$HOME/.karma/karma`) and then in `/tmp/karma/karma`;
`--find DIR` looks in that directory first, and `--place DIR` pins where the copy lives.

The program placed on the target is the artifact built for *its* platform, not the operator's: a
release's artifacts sit beside the binary (`dist/karma-linux-amd64`, `dist/karma-linux-arm64`), so an
operator on macOS audits a Linux host with `dist/karma` and the artifact next to it. A target karma
cannot be placed on — no writable and executable directory, no build for its platform — is collected
by running karma on it itself.

### Working on a target

```bash
dist/karma local mtime /var/www              # cluster directory change times; ssh and ttyd take DIR... too
dist/karma local cat /etc/passwd /etc/shadow # print files, in process
dist/karma local ls /tmp /var/tmp            # list directories the way the report's rows look
dist/karma ssh root@10.0.0.8 tainted         # one check, through the collector it places first

dist/karma ssh root@10.0.0.8 bootstrap       # place the collector and print its path, collecting nothing
dist/karma ttyd ws://10.0.0.8:7681 bootstrap
dist/karma ssh root@10.0.0.8 --place /srv/k bootstrap   # pin where it lives
```

`bootstrap` places a compressed copy of the binary on the target, verifies it and prints the path —
nothing else runs. The copy travels gzip-compressed when the target can unpack it (its own `gzip`, or
busybox's) and uncompressed when it cannot, so the mode depends on nothing the channel does not
already use. Run it on the target yourself, for example `$HOME/.karma/karma local`. This is how an
SSH or ttyd target gets the local channel's in-process checks, such as userland rootkit detection.

`mtime` walks each given directory on its own filesystem, skipping `/proc`, `/sys` and `/dev`. `cat`
and `ls` read in process rather than through the host's own binaries, so a preload hook on those
cannot reshape what they print.

### Options

`--concurrency` (default 6), `--timeout` (30s per check), `--max-lines` (400) and `--min-severity`
(default `all`) are shared by every collection. `--timeout` is the budget of one check's whole
fallback walk — its channel's own setup (a dial, a session open, the line typed into a terminal), the
command, and the last line read — so no check can take longer than that number, and a run's worst case
is `ceil(checks / concurrency) × --timeout`. The report is the output: there is no evidence bundle to
write, and a run leaves the target as it found it.

`--min-severity` is the triage knob: it names the least severe row the report keeps — `critical`,
`high`, `medium`, `low`, `info` or `benign` — or `all`, the default, which keeps the whole report.
Rows below the floor are left out and counted with the check's own filtered lines, and the header
legend says which floor is in force, so a quiet host stays readable and a busy one answers one
question. It filters the reading and nothing else.

Exit codes: 0 a run that finished, 1 a built-in reader that could not read an operand, 2 a run that
could not happen (a failed connection, or a channel that died mid-run), 70 karma's own damage — an
internal error ended the run, so the report is incomplete, and the message names the boundary that
broke — and 130 interrupted. Ctrl-C stops collection
promptly and the partial report still prints, saying how many of the selected checks were not
collected; a second Ctrl-C exits at once, which is the way out of a channel operation the context
cannot break. Errors go to stderr with a `karma: ` prefix and one plain sentence.

## Output

Every bit of the layout is drawn by lipgloss: a masthead — the `KARMA` band with the author on its
right edge, the build's version and the run's clock on the panel's own title band, and a table of
labeled facts (host, channel and the target it reached, distro, kernel, the collecting account, and how
much of the catalog ran) plus the severity key — a banner
per aspect, and a left-rail panel per check. The rail is the highest hit severity for a signal and
grey otherwise; the first line inside it carries the check id, the fallback chain, `filtered N` and
`truncated` where they apply. Long lines are soft-wrapped rather than cut, nothing is padded with
blank space, and the rows of an `ls -l` listing line up column by column.

| Severity | Presentation |
| --- | --- |
| critical | red thick rail, hit spans bold white on red |
| high | bright red thick rail |
| medium | yellow thick rail |
| low | bright cyan thick rail |

Below the hit colors sits syntax coloring — bash and PowerShell through chroma, and built-in shapes
for `ls -l`, `env`, `dmesg`, tables, `passwd`, listen tables, `ip` addresses and routes, and so on.
Color is dropped when the output is not a terminal, and `NO_COLOR`/`CLICOLOR` are honored.

The command line's own screens are that first panel too: `--help` opens with the command's band
carrying the author on its right edge, the build's version on the rail's first line, and the
command's description inside the same panel, then the usage sections as rail panels.

On Windows, PowerShell 5.1's `>` decodes karma's UTF-8 output with the console code page and
re-encodes it, so the file opens as garbage. Use cmd redirection or PowerShell 7 to keep the bytes
intact.

## Catalog

Linux aspects: `system` `identity` `process` `network` `service` `persistence` `filesystem` `log`
`kernel` `package` (76 checks). Windows aspects: `system` `identity` `process` `network`
`persistence` `execution` `navigation` `documents` `remote` `log` `timeline` `devices` (43 checks).
`karma list` prints them as a heading tree, every row carrying the check id, its title and its probe
chain; column widths are measured over the whole selection, so the groups line up.

## Development

```bash
make fmt vet test        # the gates, or each one alone
make race                # the concurrent packages under -race
make staticcheck         # when installed
make dist                # dist/ binaries, with the static-link guard
```

A tier has one body, and the tests run it over a fixture with the host tools stubbed where it needs
them (`internal/checks/linux`, `internal/checks/linux/native`), so a row, a threshold or a section
title that regresses fails there rather than on a target.

The code lives in `cmd/karma` and `internal/`: `model` is the domain, `define` builds the catalogs,
`session` runs the channels, `runner` walks the probes, `reader` reads the collected text into a
document, and `render` presents it. The catalog vocabulary (platform, aspect, check id) is also the
selector vocabulary, so what `karma list` shows is what the positional arguments accept. Each package's
own comments carry the reasoning behind its shape.

Collection is read-only: it reads files, processes, sockets and the registry; it never writes to the
target, kills a process or changes a firewall. What you see is what the current login user can see.

Two properties hold the design together. Release binaries are statically linked
(`CGO_ENABLED=0`), and the tiers read the kernel's own interfaces in process — `/proc`,
`syslog(2)`, `sock_diag`/`rtnetlink`, utmp/wtmp records, `lstat` and `debug/elf` — so neither
`LD_PRELOAD` nor a replaced host tool can change what karma reads. And a tier is one body
(`model.Native`) run wherever karma itself stands on the host: locally, or on the target through the
collector the remote channels place there. One text shape, so the same rules, filters and lexers read
it on every channel.
