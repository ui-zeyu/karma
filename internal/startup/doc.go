// Package startup reads the files a boot, login or device event acts on and
// states the activation edges they carry: which trigger names which target,
// through which mechanism, as whom, and the provenance of both ends. The audit
// judges those edges; this package only reads them.
//
// The read is deliberately structural. A unit's ExecStart, a profile's source,
// a login file's exported path and a preload assignment are the mechanisms the
// surfaces themselves define; names and descriptions are carried only for the
// operator to read.
package startup
