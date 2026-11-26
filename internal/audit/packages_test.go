package audit

import (
	"testing"

	"karma/internal/prov"
)

func TestPackageSweepSkipsDirectoriesAndSchedulerState(t *testing.T) {
	catalog := &prov.Catalog{}
	cases := []struct {
		name      string
		path      string
		ownership prov.Ownership
		want      bool
	}{
		{"a regular package file", "/usr/bin/ls", prov.Ownership{Name: "coreutils", Known: true}, true},
		{"a package directory", "/etc/systemd/system/basic.target.wants", prov.Ownership{Name: "systemd", Known: true, Dir: true}, false},
		{"an anacron stamp", "/var/spool/anacron/cron.daily", prov.Ownership{Name: "cronie", Known: true}, false},
		{"a cron spool file", "/var/spool/cron/root", prov.Ownership{Name: "cronie", Known: true}, true},
		{"a manual page", "/usr/share/man/man1/ls.1.gz", prov.Ownership{Name: "coreutils", Known: true}, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := sweepEligible(test.path, test.ownership, catalog); got != test.want {
				t.Fatalf("sweepEligible(%q) = %t, want %t", test.path, got, test.want)
			}
		})
	}
}
