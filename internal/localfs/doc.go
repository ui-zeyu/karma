// Package localfs is the in-process view of the host's filesystem behind the
// `karma local cat` and `karma local ls` readers, and the startup collector's
// non-blocking file read.
//
// No read in this package can block: every host file is opened non-blocking
// (openRegular), so a planted FIFO reads as empty or is reported, never as a
// hang.
//
// The platform-specific metadata read lives in build-tagged files; it has no
// unavailable case to report, because a host without the syscall still has
// os.FileInfo and the row shape is built from whatever it carries.
package localfs
