# karma

Read-only incident-response audit for Linux. Karma runs on the target host and
answers one question: **what appeared after the artifact was built, and what
authority can it reach?**

The version is `0.44.0`.

## Model

Every finding comes from three facts:

- **Artifact boundary** — the container's PID 1 start, or a host's last package
  transaction (a short boot window when the host has not updated since boot).
  Objects older than the boundary came with the target; objects newer arrived
  later.
- **Origin** — an object is `base` (package-owned), `provisioned` (a package
  installed after the boundary), `modified` (a package file changed), `runtime`
  (created after the boundary), `preexisting`, or `unknown`.
- **Activation and authority** — the files that decide a future execution
  (systemd, profile, cron, rc, ld.so, udev, ssh, PAM, supervisor, xdg, apt,
  modprobe) and the accounts or capabilities they run as.

Judgment reads a fourth fact on top: the **content ledger**. On a dpkg host
karma reads the package database's own per-file md5sums and compares them to
the judged files — activation targets, process images, authority objects. On an
rpm host it runs `rpm -Va`. The comparison outranks time: a hash match acquits
a file whose timestamps a package upgrade moved, a mismatch convicts a file
whose timestamps were cleaned, and a package ledger rewritten after its last
transaction is reported as tampered evidence, with that package's comparison
ignored. A package timeline from `dpkg.log` (or rpm's install ids) dates each
package's last transaction, so a file installed after the boundary reads as
provisioned. An edited conffile softens its hit one tier; an authority object
never softens.

A runtime object in an activation surface is a finding. So is a runtime setuid
binary, sudo policy, key, or credential file. Severity is the authority the
object can reach: root, a service account, a user, or the kernel. The audit also
keeps the base-space checks that need no boundary: an activation object someone
other than its owner can replace, and a running process whose image or script
was introduced after the boundary.

## Build

```bash
go build -o dist/karma ./cmd/karma     # this host
make dist                              # linux/amd64 and linux/arm64
```

## Usage

```bash
karma                                       # the whole artifact delta
karma audit                                 # the same, named
karma persistence                           # activation surfaces
karma login,kernel                          # two groups; commas and spaces are equal
karma /var/www                              # everything under a path
karma /etc/systemd/system/x.service
karma /proc/36                              # one process and its script
karma '!activity'                           # exclude a surface
```

Groups are `persistence`, `boot`, `login`, `schedule`, `service`, `device`,
`activity`, and `authority`. Surface names are `systemd`, `profile`, `init`,
`cron`, `loader`, `udev`, `ssh`, `pam`, `supervisor`, `xdg`, `apt`, `module`,
`activity`, and `authority`.

## What the report says

```text
 KARMA                                                          yuyy
▌ 0.44.0                                    2026-11-25 19:25:48 +0800
▌  host      web-1                    distro    Ubuntu 24.04
▌  account   root (uid 0)             kernel    5.15.0
▌  source    local                    ledger    dpkg · 64 pkgs · 380 hash entries · 351 verified
▌  boundary  container start 2026-11-25 06:33:28
▌  judged    32 edges · 15 proc · 17 auth · 4 svc · 4 listen
▌  severity ● critical  ● high  ● medium  ● low

▌ CRITICAL  /etc/profile.d/vendor-runtime-loader.sh
▌  runtime object in an activation surface
▌  export VENDOR_RUNTIME_LOADER in /etc/profile.d/vendor-runtime-loader.sh activates
▌  /var/lib/vendor/runtime/.attach-loader.sh
▌  origin runtime · reach root
▌  · trigger /etc/profile.d/vendor-runtime-loader.sh: runtime (created after the boundary)
▌  · no package owns it; the nearest owned ancestor /etc belongs to base-files
▌  · runs as root, reach root (profile)

 EVIDENCE
▌ ACTIVATION                                             32
▌  SURFACE     REACH         AS          ORIGIN      TRIGGER
▌  profile     login         login       runtime     /etc/profile.d/vendor-runtime-loader.sh:1
▌      export VENDOR_RUNTIME_LOADER -> /var/lib/vendor/runtime/.attach-loader.sh
...
▌ SERVICE                                                12
▌ LISTEN                                                  4
▌ AUTHORITY                                              17
▌ MOUNTS                                                 24
```

The evidence panels are the raw rows behind the findings: every activation edge,
process, systemd service, listening socket, authority object, and mount in
scope. Every finding carries its evidence lines — the origins of both ends, the
content comparison, the account it runs as, an unowned file's nearest owned
ancestor, a process's established connections. `--no-evidence` prints the
findings and coverage alone. `--json` prints the findings, services, listeners,
mounts, ledger summary, and coverage as one object.

## Options

`--since` chooses the boundary: `provision` (the default), `boot`, a duration
such as `24h`, or an RFC3339 time. `--min-severity` filters the findings.
`--timeout` bounds the whole collection in seconds. `--no-evidence` hides the
raw inventories; `--json` changes the output.

## Other modes

```bash
karma show activation                       # every edge, unjudged
karma show process                          # every process, unjudged
karma show services                         # systemd's own service inventory
karma show listeners                        # listening TCP/UDP sockets
karma show authority                        # setuid, capabilities, keys, sudoers
karma show mounts                           # the mount table
karma show coverage                         # what could not be read and why

karma cat /etc/profile.d/x.sh               # read in process, no host cat
karma ls /var/www                           # list in process
karma mtime /var/www                        # one tree by change time

karma watch proc                            # live process starts and exits
karma watch socket                          # live sockets, with the owner
```

`cat`, `ls`, `mtime`, `watch` and the audit itself read `/proc`, the kernel
interfaces and the package database in process; nothing is written and no host
tool is executed. Karma is meant to be carried to the host and run there; a
remote channel will place the binary first and then run this same local audit.

## Limits

- The model is Linux-only. Windows has no artifact boundary or activation
  inventory here.
- A boundary is only as good as the artifact. An image that already carries the
  implant reads as `base`; image signing and attestation are outside karma.
- `ctime` is the runtime signal and userland cannot set it; the content ledger
  is the stronger signal and a mismatch convicts even a cleaned timestamp. The
  residual adversary is the one who rewrites both the file and the package
  ledger and their times — the tamper check reads that as its own finding.
- A container that provisions users, packages, or configuration in its
  entrypoint writes after PID 1 starts; those objects read as runtime until the
  operator explains them.
- Memory-only code, and a base binary used with only legitimate arguments, can
  stay below the model. The process report still states deleted images,
  runtime scripts, interpreter arguments, and each process's established
  connections.
- In-guest collection can be lied to by a kernel-level rootkit. Run this build
  from read-only media, or use an out-of-band observer, when that adversary is
  in scope.
- The raw panels cover the model's own surfaces: activation, processes,
  services, listeners, authority, and mounts. Logs, kernel modules, and
  account-file contents are not collected here; use `cat`, `ls`, `mtime`, and
  `show` for the files and tables that are.
- A static vendor unit with no enablement link appears in `SERVICE` and in
  `coverage` as a running service with no activation edge; systemd starts it
  through a built-in dependency, so there is no link to follow.
- On an rpm host the content answer comes from `rpm -Va`; a host where it
  cannot finish in time reports the gap in coverage and the run falls back to
  time evidence.