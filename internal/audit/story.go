package audit

// The assessor resolves every judged object to a story: what the artifact
// shipped, what a package upgrade replaced, what something edited afterwards,
// what no ledger knows. It is the only origin writer during a report; the
// watcher keeps the time-only originOf.

import (
	"fmt"
	"path/filepath"
	"time"

	"karma/internal/trust"
)

// verdict is one object's story: the origin, the reason, the evidence lines
// that drove it, and whether a legitimate configuration edit softens the hit.
type verdict struct {
	origin   Origin
	why      string
	evidence []string
	softened bool
	// orphan is the nearest owned ancestor of a file no package owns; nil
	// when the file is owned, unknown, or not a file.
	orphan *orphanAncestor
}

// orphanAncestor is the structured answer behind an orphan's evidence
// sentence: which package owns the nearest owned directory.
type orphanAncestor struct {
	pkg    string
	dir    string
	shared bool
}

// arrived reports whether the object reached the host after the artifact
// boundary. It is the audit's core predicate: a runtime or modified origin is
// the delta the tool exists to name.
func (o Origin) arrived() bool { return o == Runtime || o == Modified }

// soften lowers a severity one tier when the story says a legitimate edit
// explains the hit. A verdict that was never softened answers unchanged.
func (v verdict) soften(severity Severity) Severity {
	if v.softened && severity > Low {
		return severity - 1
	}
	return severity
}

// against merges two ends of one relation: the weaker origin decides, and the
// softening follows the end whose origin decided. Why and evidence stay at the
// call sites, which name the ends in their own words.
func (v verdict) against(other verdict) verdict {
	merged := verdict{origin: weaker(v.origin, other.origin)}
	merged.softened = other.softened
	if v.origin.Rank() <= other.origin.Rank() {
		merged.softened = v.softened
	}
	return merged
}

type assessor struct {
	snapshot      *Snapshot
	boundary      Boundary
	times         map[string]time.Time
	verify        map[string]Content
	conffiles     map[string]bool
	tampered      map[string]bool
	mounts        mountTable
	remodifiedSet map[string]bool
	noLedger      map[string]bool
	noConffile    map[string]bool
	// unreadable names judged files whose content comparison could not run:
	// the ledger records a hash for them, the read failed. The evidence and
	// the coverage state that, so a large or unreadable file is never
	// misread as "the package records no hash".
	unreadable map[string]string
}

func newAssessor(snapshot *Snapshot) *assessor {
	a := &assessor{
		snapshot:      snapshot,
		boundary:      snapshot.Boundary,
		times:         snapshot.PackageTimes,
		verify:        snapshot.Verify,
		conffiles:     snapshot.conffiles,
		mounts:        buildMountTable(snapshot.Mounts),
		tampered:      map[string]bool{},
		remodifiedSet: map[string]bool{},
		noLedger:      map[string]bool{},
		noConffile:    map[string]bool{},
		// The unreadable set is the snapshot's own map, so files the graph
		// discovers after the collection join the same answer.
		unreadable: snapshot.unhashable,
	}
	for _, row := range snapshot.tamper {
		if row.Pkg != logLedgerPkg {
			a.tampered[row.Pkg] = true
		}
	}
	return a
}

// read reads one object's story. Authority objects — the files whose bits
// grant execution — pass readAuthority: a conffile deviation on them is an
// edited grant, and the softening stays off.
func (a *assessor) read(facts trust.Facts) verdict {
	return a.story(facts, false)
}

func (a *assessor) readAuthority(facts trust.Facts) verdict {
	return a.story(facts, true)
}

// story reads one object's evidence lines and answers its story. The
// content ledger outranks time: a match acquits a file whose timestamps a
// package upgrade moved, a mismatch convicts one whose timestamps were
// cleaned, and a tampered ledger falls back to time with a warning.
func (a *assessor) story(facts trust.Facts, authority bool) verdict {
	origin, why := originOf(facts, a.boundary, a.times)
	out := verdict{origin: origin, why: why}
	if a.mounts != nil {
		if mount, hit := a.mounts.mount(facts.Real); hit && volatileMount(mount) {
			out.evidence = append(out.evidence, fmt.Sprintf("on tmpfs at %s: the evidence dies with the boot", mount.Path))
		}
	}
	if facts.Kind != trust.File || facts.Real == "" {
		return out
	}
	if facts.PackageKnown && facts.Package == "" {
		// An orphan: the nearest owned ancestor names the tree it sits in,
		// which separates a planted payload from a home-directory tool. The
		// fact travels as data, so the report and the graph quote it without
		// re-deriving — or matching — the sentence.
		if pkg, dir, shared, ok := a.snapshot.NearestOwner(facts.Real); ok {
			out.orphan = &orphanAncestor{pkg: pkg, dir: dir, shared: shared}
			if shared {
				out.evidence = append(out.evidence, fmt.Sprintf(
					"no package owns it; the nearest owned ancestor %s is shared by several packages", dir))
			} else {
				out.evidence = append(out.evidence, fmt.Sprintf(
					"no package owns it; the nearest owned ancestor %s belongs to %s", dir, pkg))
			}
		}
		return out
	}
	if !facts.PackageKnown || facts.Package == "" {
		return out
	}
	pkg := facts.Package
	if a.tampered[pkg] {
		out.evidence = append(out.evidence, fmt.Sprintf(
			"package %s's content ledger changed after its last transaction; the content comparison is ignored", pkg))
		return out
	}
	content := a.verify[facts.Real]
	switch content.State {
	case Verified:
		if content.Method == methodRPM {
			out.evidence = append(out.evidence, fmt.Sprintf(
				"rpm -Va reports no deviation from package %s", pkg))
		} else {
			out.evidence = append(out.evidence, fmt.Sprintf(
				"content verified: md5 %s matches package %s", shortHash(content.Actual), pkg))
		}
		stamp := a.times[pkg]
		if stamp.After(a.boundary.Time) {
			out.origin = Provisioned
			out.why = fmt.Sprintf("installed by package %s at %s", pkg, stamp.Format(stampLayout))
		} else {
			out.origin = Base
			out.why = fmt.Sprintf("content matches package %s", pkg)
		}
		if !stamp.IsZero() && facts.CTime > stamp.Unix() {
			key := facts.Real
			if key == "" {
				key = facts.Path
			}
			a.remodifiedSet[key] = true
			out.evidence = append(out.evidence, fmt.Sprintf(
				"ctime %s is newer than the package's last transaction (reinstalled or touched)",
				ctimeString(facts.CTime)))
		}
	case Mismatched:
		out.origin = Modified
		out.why = fmt.Sprintf("content differs from package %s's ledger", pkg)
		if content.Method == methodRPM || content.Expected == "" {
			out.evidence = append(out.evidence, "rpm -Va reports a deviation for this path")
		} else {
			out.evidence = append(out.evidence,
				fmt.Sprintf("expected md5 %s (package %s)", shortHash(content.Expected), pkg),
				fmt.Sprintf("actual md5 %s", shortHash(content.Actual)))
		}
		if a.conffiles[facts.Real] && !authority {
			out.evidence = append(out.evidence,
				"recorded configuration file: edited content is expected, the hit is softened one tier")
			out.softened = true
		}
	default:
		// The ledger does not hash conffiles — administrators are expected
		// to edit them — so those are a named gap, not a missing ledger. A
		// file the comparison could not read states its own failure, so the
		// evidence never sends the operator to a hash row that exists.
		if a.conffiles[facts.Real] {
			a.noConffile[pkg] = true
		} else if a.unreadable[facts.Real] != "" {
			out.evidence = append(out.evidence,
				"content comparison could not read this file ("+a.unreadable[facts.Real]+"); judged by time")
		} else {
			a.noLedger[pkg] = true
			out.evidence = append(out.evidence, fmt.Sprintf(
				"package %s records no content hash for this path; judged by time", pkg))
		}
	}
	return out
}

// NearestOwner walks a path's directories to the nearest one a package owns,
// reading the facts of ancestors the run has not collected yet. It is the one
// nearest-owned-ancestor answer: the assessor's orphan evidence and the graph
// walks quote the same tree.
func (s *Snapshot) NearestOwner(path string) (pkg, dir string, shared, ok bool) {
	for dir := filepath.Dir(path); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if _, collected := s.Objects[dir]; !collected {
			s.ensureFacts([]string{dir})
		}
		facts := s.Facts(dir)
		if facts.PackageKnown && facts.Package != "" {
			return facts.Package, dir, facts.PackageShared, true
		}
	}
	return "", "", false, false
}
