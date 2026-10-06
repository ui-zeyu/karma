package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"karma/internal/model"
)

type noopObserver struct{}

func (noopObserver) CheckStarted(*model.Check)                      {}
func (noopObserver) CheckFinished(*model.Check, *model.CheckResult) {}
func (noopObserver) Damaged(*model.Check, error)                    {}

func TestSaveObserverWritesEvidenceAndManifest(t *testing.T) {
	dir := t.TempDir()
	saver := newSaveObserver(dir, "9.9.9", "ssh",
		model.HostFacts{Hostname: "web01", OsPretty: "Debian 12", Kernel: "6.1.0", UID: 0},
		io.Discard, noopObserver{})
	check := &model.Check{ID: "listen", Aspect: model.AspectNetwork}
	saver.CheckStarted(check)
	saver.CheckFinished(check, &model.CheckResult{Check: check, ProbeLabel: "ss", Raw: "rows\n"})
	saver.finalize()

	raw, err := os.ReadFile(filepath.Join(dir, "network", "listen.txt"))
	if err != nil || string(raw) != "rows\n" {
		t.Fatalf("evidence file wrong: %q, %v", raw, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Tool != "karma" || m.Version != "9.9.9" || m.Channel != "ssh" || m.Hostname != "web01" ||
		m.OS != "Debian 12" || m.Kernel != "6.1.0" || m.UID != 0 {
		t.Fatalf("manifest provenance wrong: %+v", m)
	}
	if m.Started.IsZero() || time.Since(m.Started) > time.Minute {
		t.Fatalf("started should be a recent time: %v", m.Started)
	}
	if len(m.Files) != 1 {
		t.Fatalf("manifest should carry one file: %+v", m.Files)
	}
	sum := sha256.Sum256([]byte("rows\n"))
	file := m.Files[0]
	if file.Path != "network/listen.txt" || file.Check != "listen" || file.Aspect != "network" ||
		file.Probe != "ss" || file.Bytes != len("rows\n") || file.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("manifest entry wrong: %+v", file)
	}
}

// TestManifestOrdersFilesByPath: the entries are ordered by path rather than by
// the order the workers finished in, which is what lets two runs of one host be
// diffed. The checks below finish in an order no sort would produce.
func TestManifestOrdersFilesByPath(t *testing.T) {
	dir := t.TempDir()
	saver := newSaveObserver(dir, "9.9.9", "local", model.HostFacts{}, io.Discard, noopObserver{})
	for _, check := range []*model.Check{
		{ID: "services", Aspect: model.AspectService},
		{ID: "accounts", Aspect: model.AspectIdentity},
		{ID: "listen", Aspect: model.AspectNetwork},
	} {
		saver.CheckStarted(check)
		saver.CheckFinished(check, &model.CheckResult{Check: check, Raw: "rows\n"})
	}
	saver.finalize()

	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, file := range m.Files {
		paths = append(paths, file.Path)
	}
	want := []string{"identity/accounts.txt", "network/listen.txt", "service/services.txt"}
	if !slices.Equal(paths, want) {
		t.Fatalf("manifest file order = %v, want %v", paths, want)
	}
}
