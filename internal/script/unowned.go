// The unowned-file body: what sits in the system program and library
// directories while the package database does not list it. The answer comes
// from the package manager itself — dpkg searched with one wildcard pattern per
// directory, rpm asked for every file it ships — so the comparison is the
// target's own account of what it installed. A file outside that account
// arrived some other way: a hand-built install, a vendor agent, or a payload
// (/bin/.lib.so, /usr/lib/inject.so, /bin/-t).
//
// Two implementations render that body and must agree byte for byte: this
// file's Go side (UnownedBody, the local channel) and the pipeline the ssh and
// ttyd channels run (UnownedScript). The check's test runs that pipeline
// against a fixture and requires the two to print the same rows.

package script

import (
	"slices"
	"strings"
)

// unownedAlternatives is the one symlink target a stock system points into a
// system directory: update-alternatives manages /usr/bin/awk and its kind
// through /etc/alternatives, so those links are listed by no package. Their
// targets are all the filter needs to know them.

// UnownedScript is the ssh and ttyd channels' tier. Each directory is
// canonicalized first, so usrmerge's /bin and /usr/bin are one directory read
// once; the original spellings are kept beside the canonical roots, because
// dpkg's database still records the pre-merge paths — both spellings are
// queried and the owned rows are rewritten into the canonical one, exactly
// what the local tier's canonicalRows does. The two producers are tagged and
// read by one awk pass, which needs no temporary file: the found paths and
// the package database's paths are the same strings, so a path in both maps
// is owned and everything else is the body.
//
// A missing package manager exits 127 and the chain reports no answer rather
// than an empty one; a database that lists every file found is an empty answer.

// unownedAwk is the pass that keeps the found paths the package database does
// not carry. Its rule is unownedBody's: only the marker differs, because a
// shell pipeline has no second input to read the two lists from.

// UnownedBody renders the body from the two path lists: every path the
// directories hold that the package database does not list, in byte order, one
// bare path per line. A directory holding nothing unowned renders nothing.
func UnownedBody(found, owned []string) string {
	known := make(map[string]bool, len(owned))
	for _, path := range owned {
		known[path] = true
	}
	var unowned []string
	for _, path := range found {
		if !known[path] {
			unowned = append(unowned, path)
		}
	}
	if len(unowned) == 0 {
		return ""
	}
	slices.Sort(unowned)
	return strings.Join(unowned, "\n") + "\n"
}
