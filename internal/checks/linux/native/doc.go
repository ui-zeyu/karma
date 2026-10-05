// Package native implements the Linux checks' local tier: the bodies that run
// inside karma, reading the host through its own interfaces — /proc, the utmp
// and wtmp accounting records, netlink dumps, statfs(2), the passwd-style
// tables, syslog(2) for the kernel ring buffer, and the host binaries that
// still own their data (docker, dpkg/rpm, iptables/nft, systemctl) — where the
// ssh channel runs the check's shell command instead.
//
// The filesystem side of those bodies — path word lists, listings, walks,
// greps, file reads and the file(1) classification — lives in
// internal/localfs, which is also what the built-in `karma local cat`/`ls`
// readers call. This package holds what reads a kernel or a host tool.
//
// Every body has the shape of model.Dual.Run, func(context.Context) (string,
// error), and prints the same text its shell counterpart prints, so the check's
// rules, filters, and lexers apply to either channel's output unchanged. Where
// the check's shell command and this package would otherwise spell the same
// paths or patterns twice, the check hands them in — a scan's roots, a hunt's
// name list, a walk's window — so the two channels cannot drift apart.
//
// The platform-specific reads live in build-tagged files and report
// model.ErrTierUnavailable where the host lacks the interface (no /proc, no
// statfs), which is what makes the probe chain fall to the shell tier; the local
// channel then runs that tier's script, so every tier still answers.
package native
