// Package watch turns the kernel's process and socket tables into one event
// stream. The stream is one typed shape whatever source produced it: a process
// event carries the process's provenance, a socket event carries its owner's,
// and the pipeline attaches structural flags (unowned, administrator layer,
// interpreter plus script) and the audit's verdict — origin, reach, severity —
// for the image an event runs.
//
// The sources are /proc and sock_diag polls, the kernel's proc connector, and
// conntrack notifications joined by their four-tuple to the socket table. The
// pipeline annotates through a bounded worker pool and hands the writer its
// events back in the order the source produced them.
package watch
