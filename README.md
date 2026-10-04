# karma

Semi-automatic incident-response collection: run one command on your analysis host and it reads the target without writing to it. Linux goes over local or SSH; Windows goes over the local channel (system information, accounts, processes, network, persistence, logs, and user behavior). Each check is printed as soon as it finishes, in catalog order. Output is filtered and then highlighted: hit spans are painted by severity and given a reason at the end of the line. No hit, no output.

## Build

```bash
go build -o dist/karma ./cmd/karma
dist/karma --help
```

The version is `0.7.1`; override it with `-ldflags "-X main.version=…"` and print it with `karma version`.

## Usage

Without a subcommand, karma prints its help. The local channel follows the host platform (`karma local` runs the Windows catalog on Windows and the Linux catalog elsewhere). An SSH target is always treated as Linux.

```bash
dist/karma local                          # local host, every aspect
dist/karma local network process          # aspect names
dist/karma local network,log listen       # commas and spaces are equivalent, check ids mix in

dist/karma ssh root@10.0.0.8
dist/karma ssh -p 2222 -i ~/.ssh/id_ed25519 root@10.0.0.8 persistence
dist/karma ssh ssh://root@10.0.0.8:2222
dist/karma ssh -o StrictHostKeyChecking=yes root@10.0.0.8 network,log

dist/karma local mtime /var/www
dist/karma ssh root@10.0.0.8 mtime /var/www /opt

dist/karma list
dist/karma list network
```

A selector word is a platform name, an aspect name, or a check id; with none given, everything runs. A platform or aspect word counts only if the catalog carries it, so `karma list windows` selects one platform's catalog and `karma list persistence` selects that aspect on both; an unknown word is an error with close matches. The first positional argument of `karma ssh` is the target. mtime hangs below `local` and `ssh` and clusters directory change times (the walk stays on each directory's own filesystem and skips `/proc`, `/sys` and `/dev`); over SSH the connection parameters (-p/-i/-o/--password) are written after the target as usual.

Linux aspects: `system` `identity` `process` `network` `service` `persistence` `filesystem` `log` `kernel` `package` (70 checks). Windows aspects: `system` `identity` `process` `network` `persistence` `execution` `navigation` `documents` `remote` `log` `timeline` `devices` (42 checks). `karma list` lists both platforms' catalogs as a two-level heading tree — one band per platform, one band per aspect — and every row carries the check id, the title, and the probe chain. Column widths are measured over the whole selection, so the groups line up and a long title wraps inside its own column.

Shared options: `--concurrency` defaults to 6, `--timeout` to 30 seconds, `--max-lines` to 400. With `--save DIR`, every check that collected output writes the target's raw stdout to `<DIR>/<aspect>/<check id>.txt` — the bytes exactly as the channel delivered them, before any reading, filtering, or normalization — one directory per aspect, overwriting same-named files on a repeated run.

SSH: `-p` port, `-i` private key (repeatable), `--password` for password authentication (it also unlocks an encrypted private key). The password comes from that flag alone; without it karma uses public keys and exits when authentication fails. An identity that cannot be used (say, a passphrase-protected key with no `--password`) is skipped; that failure surfaces only when nothing is left to authenticate with. `-o` accepts only `StrictHostKeyChecking=no|accept-new|yes`, defaulting to `no`. A failed connection exits 2.

Errors always go to stderr with the `karma: ` prefix and one plain sentence: an unknown command gets close commands (`lst` → `list`), a name mounted elsewhere (`mtime`) gets the way to write it, an unknown flag gets that command's flag list, and a bad value gets one line. Usage and help text is cobra's standard English. Exit codes: 0 for a run that finished and for a mistake the message already explained, 2 for a run that could not happen (a failed connection).

## Output

Every bit of the layout is drawn by lipgloss. The report header is one rounded box carrying the host facts and the severity legend. An aspect is a banner filling the line width (dark background, uppercase white text). A check is a left-rail panel: the rail is a half block, carrying the highest hit severity for a signal and grey otherwise; the first line inside the rail is the bold check id with the fallback chain, `filtered N`, and `truncated` on the right, and the body is indented two more columns. Sources (files, commands) are separated into sections by a bold default-color title, with one blank line between sources. Over-long lines are never truncated: lipgloss soft-wraps them, continuation lines share the body indent, and the rail stays unbroken. The report presents evidence only — a check that was never collected does not appear, exactly like one that was collected with no content. A rendering failure (odd target output hitting a line shape) does not interrupt the run: that check falls back to a thin grey rail with its raw text, and the remaining checks carry on.

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
