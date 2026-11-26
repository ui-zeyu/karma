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

The run reads only the domains the command selects: services, processes,
network, persistence, authority, identity, files, packages, web and kernel. A
services audit reads unit files, systemd's inventory and the package ledger; a
files audit reads program directories and the package file lists; an identity
audit parses accounts, groups, sudo grants, shadow state and SSH keys; a
packages audit sweeps every package file list against its package transaction;
a web audit follows web-root scripts; a kernel audit reads the module
registries, the taint mask, the pid space and the dynamic loader's search path.
The bare audit reads every bounded domain. `karma audit files <path>` extends
the static inventory to a tree you name.

The newer domains are graphs, not text dumps:

- **identity** — account, group, shadow, sudo grant, authorized key and
  `sshd_config` are nodes; membership, NOPASSWD, forced-command and
  `AuthorizedKeysFile` are edges. One account with UID 0, an empty password, a
  privileged group and a passwordless grant becomes one `identity-backdoor`
  finding with the independent paths in its chain.
- **network** — process → socket → peer. An interpreter that holds an
  established connection is a reverse-shell shape; a shell or raw-socket tool
  on a listener is a bind-shell shape. The peer is evidence, not a keyword.
- **packages** — package → file. Every package file is stat'ed against its
  package's last transaction; a later ctime is a broken ownership edge, and a
  missing path is a broken file edge. The content ledger remains the precise
  answer for judged files; this sweep is global and time-based.
- **boot** — every activation surface as trigger → mechanism → target edges:
  systemd units and generators, profiles, cron, init scripts, `ld.so.preload`,
  udev, ssh daemon and client commands, PAM stacks and `pam_exec`, NSS modules,
  `update-motd.d`, xinetd `server=`, TCP wrappers and the boot configuration
  (`fstab`, `crypttab`).
- **web** — web root → script, with the script's origin and package story.
- **kernel** — loaded and dormant module files, registry disagreements, hidden
  pids, taint and the dynamic loader's search path.

`karma graph <identity|authority|network|packages|boot|web|kernel>` prints one
domain as a relation graph; findings come first, then the nodes and edges.

The kernel domain joins the model at the artifact: every loaded module's `.ko`
file is judged by origin and reach like any other object. The registries that
describe the same modules (`/proc/modules`, `/sys/module` and the module tags in
`/proc/kallsyms`) are compared, so a rootkit that scrubs one view is caught by
the others; a module the kernel schedules but `/proc` does not list is a
finding, as is a pid `kill(0)` can signal that `/proc` hides. The dynamic
loader's configuration and search directories are read too: an unowned library
on that path, or a loader directory a non-root account can write, is evidence
against every process that loads it.

`karma graph` adds the other half: relations. A domain word draws that domain's
graph; any other word names one object — a unit, a pid, a path or a package —
and the graph grows from it. It reads the unit's declared edges, the kernel's
cgroup and open/mapped files, ELF and JAR dependencies, the application tree
the object sits in, and path-like strings in its content. Each edge says which
source produced it (kernel, unit, package, tree, shell, elf, jar, cmdline,
lexical) and how strongly. Findings still come from origin and reach; a
lexical lead only widens the review.

## Build

```bash
go build -o dist/karma ./cmd/karma     # this host
make dist                              # linux/amd64 and linux/arm64
```

## Usage

```bash
karma                                       # every bounded domain
karma audit                                 # the same, named
karma audit services                        # unit files and systemd's inventory
karma audit services ssh.service            # one unit
karma audit processes                       # the live process table
karma audit network                         # listeners and their owners
karma audit persistence                     # profile, cron, rc, loader, udev, ...
karma audit authority                       # setuid, setgid, caps, sudoers, keys
karma audit identity                        # accounts, groups, sudo, shadow, SSH keys
karma audit files                           # program directories against the package lists
karma audit files /opt /usr/lib             # the inventory over named trees
karma audit packages                        # every package file against its transaction
karma audit web                             # web-root script provenance
karma audit kernel                          # modules, dormant .ko, hidden pids, taint, loader

karma graph identity                        # account/group/sudo/key relation graph
karma graph network                         # process/socket/peer graph
karma graph packages                        # package/file provenance graph
karma graph boot                            # boot/login TCB graph
karma graph web                             # web root/script graph
karma graph kernel                          # module registry graph

karma graph ssh.service                     # one object's relation graph
karma graph 1681                            # a pid, its image, cgroup, files, sockets
karma graph /etc/profile.d/vendor.sh        # a path and what names it
karma graph pkg:openssh-server              # a package and its judged files
```

Domains are `services`, `processes`, `network`, `persistence`, `authority`,
`identity`, `files`, `packages`, `web`, and `kernel`. Surface names are
`systemd`, `profile`, `init`, `cron`, `loader`, `udev`, `ssh`, `pam`,
`supervisor`, `xdg`, `apt`, `module`, `system`, `activity`, and `authority`;
groups are `persistence`, `boot`, `login`, `schedule`, `service`, `device`,
and `activity`. A path prefix, `/proc/<pid>`, a unit name, or `!word` narrows
or excludes.

## What the report says

```text
 KARMA                                                          yuyy
▌ 0.44.0                                    2026-11-25 19:25:48 +0800
▌  host      web-1                    distro    Ubuntu 24.04
▌  account   root (uid 0)             kernel    5.15.0
▌  source    local                    ledger    dpkg · 64 pkgs · 380 hash entries · 351 verified
▌  boundary  container start 2026-11-25 06:33:28
▌  judged    32 edges · 15 proc · 17 auth · 4 svc · 4 listen · 62 mod
▌  severity ● critical  ● high  ● medium  ● low

▌ CRITICAL  /etc/profile.d/vendor-runtime-loader.sh
▌  runtime object in an activation surface
▌  export VENDOR_RUNTIME_LOADER in /etc/profile.d/vendor-runtime-loader.sh activates
▌  /var/lib/vendor/runtime/.attach-loader.sh
▌  origin runtime · reach root
▌  · chain  profile → /etc/profile.d/vendor-runtime-loader.sh → runtime
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
scope. They are hidden by default; `--evidence` prints them (the `EVIDENCE`
block above). Every finding always carries its evidence lines — the origins of
both ends, the content comparison, the account it runs as, an unowned file's
nearest owned ancestor, a process's established connections. `--json` prints the
findings, services, listeners, mounts, ledger summary, and coverage as one object.

The text views carry their heuristics on a terminal: evidence and `show` rows
color the origin column (runtime warm red, modified/unknown amber, provisioned
calm, base muted), service states (active green, failed red, transition amber),
socket states (LISTEN amber, established cyan) and mount types (remote cyan,
memory-backed amber). `karma ls` wears the ls -l palette (permissions by bit,
fresh dates green, names by file kind), and `karma cat` paints shell and
PowerShell scripts, ssh configs and key/value files. A pipe gets plain bytes.

## Graph

`karma graph <domain|object>` prints the findings that touch the graph, then
one tree. A node is a unit, process, file, package, socket, or directory. `!`
marks a runtime or modified object, `?` a missing or unknown one. An edge
names its kind and source, for example `execstart[unit]`, `runs[cgroup]`,
`open[kernel]`, `linked[elf]`, `references[shell]`, or `mentions[lexical]`.

```text
unit attachment-previewd.service  runtime  created after the boundary
├─ configured-by[unit] file /etc/systemd/system/attachment-previewd.service
├─ environmentfile[unit] file /etc/systemd/system/attachment-previewd.env
└─ execstart[unit] file /usr/local/libexec/attachment-previewd
   ├─ in-tree[tree] dir /usr/local/libexec
   └─ interpreter[shebang] file /bin/bash
```

An object seed scopes the collection: a unit reads only that unit's systemd
files and `systemctl show`, the processes in its cgroup, and their sockets; a
pid reads that process and its parent; a path reads every startup surface and
follows the objects that name it. A domain seed reads that domain. `--json`
prints nodes, edges, findings, and coverage.

## Options

`--since` chooses the boundary: `provision` (the default), `boot`, a duration
such as `24h`, or an RFC3339 time. `--min-severity` filters the findings.
`--timeout` bounds the whole collection in seconds (default 120; the package
sweep and authority walk are the expensive domains). `--evidence` prints the
raw inventories behind the findings; `--json` changes the output and carries
each finding's graph chain.

## Other modes

```bash
karma show activation                       # every edge, unjudged
karma show process                          # every process, unjudged
karma show services                         # systemd's own service inventory
karma show listeners                        # listening TCP/UDP sockets
karma show connections                      # established TCP peers
karma show kernel                           # loaded modules and the taint mask
karma show authority                        # setuid, capabilities, keys, sudoers
karma show mounts                           # the mount table
karma show coverage                         # what could not be read and why

karma cat /etc/profile.d/x.sh               # read in process, no host cat
karma ls /var/www                           # list in process
karma ctime /var/www                        # one tree by inode change time

karma watch proc                            # live process starts and exits
karma watch socket                          # live sockets, with the owner
```

`cat`, `ls`, `ctime`, `watch` and the audit itself read `/proc`, the kernel
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
- In-guest collection can be lied to by a kernel-level rootkit that hooks
  `/proc`, sysfs, kallsyms, `kill(0)` and the loader at once. The kernel domain
  makes a single-view scrub visible; run this build from read-only media or use
  an out-of-band observer when that adversary is in scope.
- Kernel memory ownership (`/proc/vmallocinfo`, `/proc/kcore`) is not read: an
  LKM that scrubs every registry and symbol table leaves only its memory image,
  which this build does not scan. The module-file, registry, taint and hidden-pid
  checks still run. The content ledger hashes the judged files, not every package
  file; a whole-package `dpkg -V`/`rpm -Va` sweep is outside the run.
- The raw panels cover the model's own surfaces: activation, processes,
  services, listeners, connections, authority, mounts, and kernel modules. Log
  contents are not collected here; use `cat`, `ls`, `ctime`, and `show` for the
  files and tables that are. Identity files are parsed into account relations,
  not printed.
- The package sweep is a ctime comparison against each package transaction; it
  does not hash every package file. The content ledger remains the precise,
  scoped answer. A kernel-level attacker who forges ctime defeats the sweep.
- Web findings are origin-based. A webshell baked into the base image is
  `base`; content-signature scanning is not part of the default run.
- Activation objects in stable administrator trees are judged by origin and
  package ownership. Volatile files such as `/etc/resolv.conf` and `/etc/hosts`
  are left to the network context, because DHCP and cloud-init rewrite them.
- The authority walk covers program trees, `/home`, `/root`, `/srv`,
  `/var/tmp`, `/var/www`, `/var/spool`, `/tmp` and `/dev/shm`; administrator
  tool caches and container/image stores under `/var/lib` are skipped, and the
  coverage says when the walk hits its file limit.
- A static vendor unit with no enablement link appears in `SERVICE` and in
  `coverage` as a running service with no activation edge; systemd starts it
  through a built-in dependency, so there is no link to follow.
- On an rpm host the content answer comes from `rpm -Va`; a host where it
  cannot finish in time reports the gap in coverage and the run falls back to
  time evidence.
- The static inventory defaults to the program directories. `files <path>`
  extends it; the audit never walks the whole disk. Generated files under
  `/usr/lib` are only reviewed when you name that tree.
- A profile reads declared metadata, kernel state, the application tree, ELF
  and JAR dependencies, and path-shaped strings. A reference built at runtime
  that none of those exposes is counted in coverage, not guessed. Config
  formats are not parsed for includes; a config is reviewed as a file and its
  text only for path-like leads.
