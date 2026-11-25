// Package netdiag reads the kernel's socket table and the processes that hold
// its sockets. It is the one reader behind the socket watcher.
//
// The table itself comes from sock_diag, not from /proc/net: the diag dump
// carries the socket inode and every TCP state, and it is the interface ss
// reads. The owning process is not in the dump, so /proc/[pid]/fd is walked for
// the inodes the caller asked about, the same step ss -p performs.
package netdiag
