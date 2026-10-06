package main

import (
	"os"
	"regexp"
	"testing"
)

// versionSites are the three places the release version is written by hand: the
// entry point the build stamps, the Makefile that builds the release binaries,
// and the README a reader takes the version from. A release that updates one of
// them and not the others ships a binary whose own documentation disagrees with
// it, and no other test reads all three.
var versionSites = []struct {
	file  string
	value *regexp.Regexp
}{
	{"main.go", regexp.MustCompile(`(?m)^var version = "([^"]+)"$`)},
	{"../../Makefile", regexp.MustCompile(`(?m)^VERSION \?= (\S+)$`)},
	{"../../README.md", regexp.MustCompile("The version is `([^`]+)`")},
}

var releaseShape = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func TestTheVersionIsWrittenTheSameWayInAllThreePlaces(t *testing.T) {
	versions := map[string]string{}
	for _, site := range versionSites {
		body, err := os.ReadFile(site.file)
		if err != nil {
			t.Fatalf("%s: %v", site.file, err)
		}
		found := site.value.FindAllStringSubmatch(string(body), -1)
		if len(found) != 1 {
			t.Fatalf("%s should name the version once (%s), found %d", site.file, site.value, len(found))
		}
		versions[site.file] = found[0][1]
	}
	release := versions["main.go"]
	if !releaseShape.MatchString(release) {
		t.Errorf("the version should read major.minor.patch, got %q", release)
	}
	for _, site := range versionSites {
		if versions[site.file] != release {
			t.Errorf("%s says %s, main.go says %s", site.file, versions[site.file], release)
		}
	}
}
