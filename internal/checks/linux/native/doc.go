// Package native implements the Linux catalog's tier bodies: the code that runs
// inside karma, reading the host through its own interfaces — /proc, the utmp
// and wtmp accounting records, netlink dumps, statfs(2), the passwd-style
// tables, syslog(2) for the kernel ring buffer, and the host binaries that
// still own their data (docker, dpkg/rpm, iptables/nft, systemctl).
//
// The filesystem side of those bodies — path word lists, listings, walks,
// greps, file reads and the file(1) classification — lives in
// internal/localfs, which is also what the built-in `karma local cat`/`ls`
// readers call. This package holds what reads a kernel or a host tool.
//
// Every body has the shape of model.Native.Body, func(context.Context) (string,
// error), and returns the text the check's rules, filters and lexers read. These
// bodies are the native source's reading: they run where karma itself stands,
// which is why the check that declares one declares the sh source's spelling of
// the same evidence beside it rather than in its fallback chain. Where a check
// and this package would otherwise spell the same paths or patterns twice, the
// check hands them in — a scan's roots, a hunt's name list, a walk's window — so
// a rule and the rows it grades cannot drift apart.
//
// The platform-specific reads live in build-tagged files and report
// model.ErrTierUnavailable where the host lacks the interface (no /proc, no
// statfs), which is what makes the probe chain fall to the next tier; the
// listing reads that need no /proc answer on any host.
package native
