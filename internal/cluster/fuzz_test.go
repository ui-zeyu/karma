package cluster

import (
	"math"
	"testing"
)

func FuzzParseFindRowAndEntry(f *testing.F) {
	f.Add("1750000000.5\t1750000001.25\t2025-06-15 10:26:40.5\t10:26:40.5\t4096\t/etc/passwd")
	f.Add("1\t2\t3\t4\t5\tpath with spaces")
	f.Add("1\t2\tx\t4\t5\tp")
	f.Add("short")
	f.Add("-1\t-2\t3\t4\t-5\t/p")
	f.Fuzz(func(t *testing.T, line string) {
		if row := ParseFindRow(line); row != nil {
			if math.IsNaN(row.Mtime) || math.IsInf(row.Mtime, 0) ||
				math.IsNaN(row.Ctime) || math.IsInf(row.Ctime, 0) {
				t.Fatalf("parsed %q to non-finite epochs: %+v", line, row)
			}
			if row.Stamp == "" {
				t.Fatalf("parsed %q to an empty stamp", line)
			}
		}
		if entry := ParseEntry(line); entry != nil && (math.IsNaN(entry.Mtime) || math.IsInf(entry.Mtime, 0)) {
			t.Fatalf("parsed %q to a non-finite epoch: %+v", line, entry)
		}
	})
}
