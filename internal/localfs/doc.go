// Package localfs is the local channel's in-process view of the host's
// filesystem, standing in for the shell and the host tools the ssh channel
// runs: pathname expansion and $(uname -r) from the shell, and cat, tail, ls,
// find, grep and file from the tools.
//
// Every function reproduces its shell counterpart's text exactly — a file read
// keeps the ReadFiles section shape, a listing keeps the find -printf row shape
// the ls-l lexer speaks, a content scan keeps grep's `path:line:text` rows — so
// a check's rules, filters and lexers apply to either channel's output
// unchanged. What becomes Go here is the shell-level plumbing: globs, word
// lists, loops and pipes.
//
// Nothing here knows about checks or the report. The Linux catalog composes
// these primitives for the tiers that read the filesystem in process, the tiers
// that read a kernel interface live in internal/checks/linux/native, and the
// built-in `karma local cat` / `local ls` readers are a thin shell over Cat and
// Ls.
//
// The platform-specific metadata read lives in build-tagged files; it has no
// unavailable case to report, because a host without the syscall still has
// os.FileInfo and the row shape is built from whatever it carries.
package localfs
