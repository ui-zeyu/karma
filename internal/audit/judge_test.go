package audit

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// classPrefixes are the shapes a finding class spells; any quoted word in the
// audit package that matches one is a class and must be routed to a domain.
var classPrefixes = []string{
	"activation-", "identity-", "module-", "kernel-", "loader-", "authority-",
	"process-", "interpreter-", "package-file-", "web-", "clock-",
	"hidden-", "future-", "ledger-", "runtime-", "deleted-", "unowned-", "unit-",
}

func TestEveryFindingClassIsRoutedToADomain(t *testing.T) {
	// A class appears as a literal after `Class:`, as the value a small
	// switch returns, or as the `class :=` variable a case fills.
	literal := regexp.MustCompile(`(?:Class:\s*|class\s*:=\s*|class,\s*title\s*=\s*|return\s+)"([a-z][a-z0-9]*(?:-[a-z0-9]+)+)"`)
	var missing []string
	scan := func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range literal.FindAllString(string(data), -1) {
			token = strings.Trim(token, `"`)
			for _, prefix := range classPrefixes {
				if strings.HasPrefix(token, prefix) {
					if classDomain[token] == 0 {
						missing = append(missing, path+": "+token)
					}
					break
				}
			}
		}
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scan(name)
	}
	if len(missing) > 0 {
		t.Errorf("finding classes without a domain route:\n%s", strings.Join(missing, "\n"))
	}
}

func TestGraphWordsCoverTheDomains(t *testing.T) {
	for word, bit := range graphDomain {
		if bit == 0 {
			t.Errorf("graph word %q maps to no domain", word)
		}
	}
	for _, word := range []string{"identity", "authority", "network", "packages", "boot", "web", "kernel"} {
		if _, ok := graphDomain[word]; !ok {
			t.Errorf("graph word %q missing from the domain table", word)
		}
	}
}
