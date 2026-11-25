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
}

type assessor struct {
	boundary   Boundary
	times      map[string]time.Time
	verify     map[string]Content
	conffiles  map[string]bool
	tampered   map[string]bool
	owners     map[string]string
	mounts     mountTable
	remodified int
	noLedger   map[string]bool
	noConffile map[string]bool
}

func newAssessor(snapshot *Snapshot) *assessor {
	a := &assessor{
		boundary:   snapshot.Boundary,
		times:      snapshot.PackageTimes,
		verify:     snapshot.Verify,
		conffiles:  snapshot.conffiles,
		mounts:     buildMountTable(snapshot.Mounts),
		tampered:   map[string]bool{},
		owners:     map[string]string{},
		noLedger:   map[string]bool{},
		noConffile: map[string]bool{},
	}
	for _, row := range snapshot.tamper {
		if row.Pkg != logLedgerPkg {
			a.tampered[row.Pkg] = true
		}
	}
	for path, facts := range snapshot.Objects {
		if facts.PackageKnown && facts.Package != "" {
			a.owners[path] = facts.Package
		}
	}
	for path, pkg := range snapshot.ownerOf {
		if _, seen := a.owners[path]; !seen {
			a.owners[path] = pkg
		}
	}
	return a
}

// verdict reads one object's evidence lines and answers its story. The
// content ledger outranks time: a match acquits a file whose timestamps a
// package upgrade moved, a mismatch convicts one whose timestamps were
// cleaned, and a tampered ledger falls back to time with a warning.
func (a *assessor) read(facts trust.Facts, authority bool) verdict {
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
		// which separates a planted payload from a home-directory tool.
		if pkg, dir, ok := a.ancestorOwner(facts.Real); ok {
			out.evidence = append(out.evidence, fmt.Sprintf(
				"no package owns it; the nearest owned ancestor %s belongs to %s", dir, pkg))
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
		out.evidence = append(out.evidence, fmt.Sprintf(
			"content verified: md5 %s matches package %s", shortHash(content.Actual), pkg))
		stamp := a.times[pkg]
		if stamp.After(a.boundary.Time) {
			out.origin = Provisioned
			out.why = fmt.Sprintf("installed by package %s at %s", pkg, stamp.Format(stampLayout))
		} else {
			out.origin = Base
			out.why = fmt.Sprintf("content matches package %s", pkg)
		}
		if !stamp.IsZero() && facts.CTime > stamp.Unix() {
			a.remodified++
			out.evidence = append(out.evidence, fmt.Sprintf(
				"ctime %s is newer than the package's last transaction (reinstalled or touched)",
				ctimeString(facts.CTime)))
		}
	case Mismatched:
		out.origin = Modified
		out.why = fmt.Sprintf("content differs from package %s's ledger", pkg)
		if content.Expected == "" {
			out.evidence = append(out.evidence, "rpm -Va reports a content deviation for this path")
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
		// to edit them — so those are a named gap, not a missing ledger.
		if a.conffiles[facts.Real] {
			a.noConffile[pkg] = true
		} else {
			a.noLedger[pkg] = true
		}
		out.evidence = append(out.evidence, fmt.Sprintf(
			"package %s records no content hash for this path; judged by time", pkg))
	}
	return out
}

// ancestorOwner walks a path's directories to the nearest one a package owns.
func (a *assessor) ancestorOwner(path string) (string, string, bool) {
	for dir := filepath.Dir(path); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if pkg, ok := a.owners[dir]; ok {
			return pkg, dir, true
		}
	}
	return "", "", false
}
