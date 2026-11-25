package startup

import (
	"encoding/base64"
	"testing"
)

func b64(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }

func TestParseCorpusRejectsBadHeader(t *testing.T) {
	cases := []string{
		"",
		"KARMA-STARTUP 2\n",
		"not the header\n",
	}
	for _, text := range cases {
		if _, err := ParseCorpus(text); err == nil {
			t.Errorf("ParseCorpus(%q) accepted a foreign header", text)
		}
	}
}

func TestParseCorpusRejectsUnknownLine(t *testing.T) {
	text := protocolHeader + "\nZ nope\n"
	if _, err := ParseCorpus(text); err == nil {
		t.Error("an unknown tag should be an error, not a dropped file")
	}
}

// An E line states a file the target could not read; it is not a file body and
// must not enter the analysis, only the coverage note.
func TestParseCorpusUnreadable(t *testing.T) {
	path := "/etc/profile"
	wire := protocolHeader + "\nE " + b64(path) + "\n"
	corpus, err := ParseCorpus(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus.files) != 0 {
		t.Errorf("an unreadable path should not enter the corpus: %+v", corpus.files)
	}
	if got := corpus.Unreadable(); len(got) != 1 || got[0] != path {
		t.Errorf("unreadable = %v", got)
	}
}

func TestParseCorpusNoManager(t *testing.T) {
	path := "/usr/bin/worker"
	wire := protocolHeader + "\n" +
		"P " + b64(path) + " f 755 0 0 0 " + b64(path) + " 0 0 0 0 0 0 0\n"
	corpus, err := ParseCorpus(wire)
	if err != nil {
		t.Fatal(err)
	}
	if facts := corpus.facts(path); facts.PackageKnown {
		t.Errorf("a corpus with no manager must read as unknown: %+v", facts)
	}
}

func TestParseCorpusPackageRows(t *testing.T) {
	path := "/usr/bin/true"
	wire := protocolHeader + "\n" +
		"D 1\n" +
		"O dpkg\n" + b64("coreutils: "+path+"\n") + "\n" +
		"P " + b64(path) + " f 755 0 0 0 " + b64(path) + " 0 0 0 0 0 0 0\n"
	corpus, err := ParseCorpus(wire)
	if err != nil {
		t.Fatal(err)
	}
	facts := corpus.facts(path)
	if facts.Package != "coreutils" || !facts.PackageKnown {
		t.Errorf("fact = %+v", facts)
	}

	unowned := "/usr/local/bin/agent"
	wire = protocolHeader + "\n" +
		"D 1\n" +
		"O dpkg\n" + b64("") + "\n" +
		"P " + b64(unowned) + " f 755 0 0 0 " + b64(unowned) + " 0 0 0 0 0 0 0\n"
	corpus, err = ParseCorpus(wire)
	if err != nil {
		t.Fatal(err)
	}
	facts = corpus.facts(unowned)
	if !facts.PackageKnown || facts.Package != "" {
		t.Errorf("an absent batch row must read as unowned: %+v", facts)
	}
}

func TestParseCorpusRPMRows(t *testing.T) {
	path := "/usr/bin/true"
	wire := protocolHeader + "\n" +
		"R 1\n" +
		"O rpm\n" + b64("coreutils "+path+"\n") + "\n" +
		"P " + b64(path) + " f 755 0 0 0 " + b64(path) + " 0 0 0 0 0 0 0\n"
	corpus, err := ParseCorpus(wire)
	if err != nil {
		t.Fatal(err)
	}
	if facts := corpus.facts(path); facts.Package != "coreutils" || !facts.PackageKnown {
		t.Errorf("fact = %+v", facts)
	}
}
