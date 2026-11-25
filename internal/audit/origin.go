package audit

import (
	"fmt"
	"time"

	"karma/internal/trust"
)

// originOf places one object against the artifact boundary. Package ownership
// is the strong answer when it exists; ctime is the answer for everything the
// package database does not carry, and userland cannot write it.
func originOf(facts trust.Facts, boundary Boundary, packageTimes map[string]time.Time) (Origin, string) {
	if facts.Kind != trust.File && facts.Kind != trust.Dir {
		return Unknown, "not a file or directory"
	}
	if boundary.Time.IsZero() {
		return Unknown, "no artifact boundary"
	}
	if facts.PackageKnown && facts.Package != "" {
		if stamp, ok := packageTimes[facts.Package]; ok && stamp.After(boundary.Time) {
			return Provisioned, fmt.Sprintf("installed by package %s at %s", facts.Package, stamp.Format(stampLayout))
		}
		if facts.CTime > boundary.Time.Unix() {
			return Modified, fmt.Sprintf("package %s file changed after the boundary (%s)", facts.Package, ctimeString(facts.CTime))
		}
		return Base, fmt.Sprintf("owned by package %s", facts.Package)
	}
	if facts.CTime == 0 {
		return Unknown, "no change time"
	}
	if facts.CTime <= boundary.Time.Unix() {
		return PreExisting, "older than the boundary (" + ctimeString(facts.CTime) + ")"
	}
	return Runtime, "created after the boundary (" + ctimeString(facts.CTime) + ")"
}

// weaker answers the less trustworthy of two origins. The lattice's rank is
// ordered worst first, so the smaller rank wins.
func weaker(left, right Origin) Origin {
	if left.Rank() <= right.Rank() {
		return left
	}
	return right
}

const stampLayout = "2006-01-02 15:04:05"

func ctimeString(seconds int64) string {
	if seconds == 0 {
		return "unknown"
	}
	return time.Unix(seconds, 0).Format(stampLayout)
}
