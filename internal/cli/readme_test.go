package cli

// The README names the vocabulary the commands answer to. This test reads the
// same lists from the registries, so a new domain or surface cannot ship with
// prose that no longer describes the tool.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"karma/internal/audit"
	"karma/internal/startup"
)

func TestREADMEListsMatchTheRegistries(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(readme)

	domains := backtickedList(t, text, "Domains are ", ". Surface names are")
	assertSameWords(t, "domains", domains, audit.DomainWords())

	surfaces := backtickedList(t, text, "Surface names are", "groups are")
	assertSameWords(t, "surfaces", surfaces, startup.SurfaceWords())

	groupNames := backtickedList(t, text, "groups are", ". A path prefix")
	names := make([]string, 0, len(groups))
	for group := range groups {
		names = append(names, group)
	}
	assertSameWords(t, "surface groups", groupNames, names)

	graph := strings.Split(graphWordList(t, text), "|")
	assertSameWords(t, "graph words", graph, audit.GraphWords())
}

// backtickedList reads the backticked words of one sentence frame.
func backtickedList(t *testing.T, text, start, end string) []string {
	t.Helper()
	at := strings.Index(text, start)
	if at < 0 {
		t.Fatalf("README lacks %q", start)
	}
	rest := text[at+len(start):]
	if stop := strings.Index(rest, end); stop >= 0 {
		rest = rest[:stop]
	}
	return backticks(rest)
}

// graphWordList reads the `<a|b|c>` words of the graph usage line.
func graphWordList(t *testing.T, text string) string {
	t.Helper()
	at := strings.Index(text, "`karma graph <")
	if at < 0 {
		t.Fatalf("README lacks the karma graph usage line")
	}
	rest := text[at+len("`karma graph <"):]
	stop := strings.Index(rest, ">")
	if stop < 0 {
		t.Fatal("the karma graph usage line never closes its list")
	}
	return rest[:stop]
}

// backticks answers every `word` in the text, in order.
func backticks(text string) []string {
	var words []string
	for {
		start := strings.Index(text, "`")
		if start < 0 {
			return words
		}
		text = text[start+1:]
		stop := strings.Index(text, "`")
		if stop < 0 {
			return words
		}
		words = append(words, text[:stop])
		text = text[stop+1:]
	}
}

// assertSameWords compares two word lists without order.
func assertSameWords(t *testing.T, what string, got, want []string) {
	t.Helper()
	left, right := append([]string(nil), got...), append([]string(nil), want...)
	sort.Strings(left)
	sort.Strings(right)
	if strings.Join(left, ",") != strings.Join(right, ",") {
		t.Errorf("README %s = [%s], the registry answers [%s]", what,
			strings.Join(got, ", "), strings.Join(want, ", "))
	}
}
