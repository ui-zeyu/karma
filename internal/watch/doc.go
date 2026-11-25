// Package watch turns the kernel's process and socket tables into one event
// stream, a poll at a time. The stream is the same shape whatever source
// produced it: an exec or exit carries the process's provenance, a socket
// carries the owner's, and both are annotated with structural facts (unowned,
// administrator layer, interpreter plus script) rather than names. An exec
// event also states the audit's origin, reach and severity for the image it
// runs.
//
// The first source is the universal one: /proc for processes and sock_diag for
// sockets, both read-only and available in a default container. The interface
// is the seam the eBPF, perf-tracepoint and connector sources land behind
// without changing the renderer or the annotation.
package watch
