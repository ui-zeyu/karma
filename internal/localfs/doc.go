// Package localfs is the native source's in-process view of the host's
// filesystem, standing in for the shell and the host tools the sh source runs:
// pathname expansion and $(uname -r) from the shell, and cat, tail, ls, find,
// grep and file from the tools.
//
// Every function reproduces its shell counterpart's text exactly — a file read
// answers with the file's own bytes, a listing keeps the find -printf row shape
// the ls-l lexer speaks, a content scan keeps grep's `path:line:text` rows — so
// a check's rules, filters and lexers apply to either source's output
// unchanged. What becomes Go here is the shell-level plumbing: globs, word
// lists, loops and pipes, and the list a file-list tier answers with.
//
// Nothing here knows about checks or the report. The Linux catalog composes
// these primitives for the tiers that read the filesystem in process, the tiers
// that read a kernel interface live in internal/checks/linux/native, and the
// built-in `karma local cat` / `local ls` readers are a thin shell over Cat and
// Ls.
//
// No read in this package can block: every host file is opened non-blocking
// (openRegular), so a planted FIFO reads as empty or is reported, never as a
// hang. Nothing above can recover from the alternative — an in-process tier's
// deadline abandons a body parked in a syscall rather than breaking it, so a
// blocking open in this layer would silently cost the tier its evidence and leak
// the goroutine for good.
//
// The platform-specific metadata read lives in build-tagged files; it has no
// unavailable case to report, because a host without the syscall still has
// os.FileInfo and the row shape is built from whatever it carries.
package localfs
