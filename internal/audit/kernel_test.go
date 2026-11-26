package audit

import (
	"strings"
	"testing"

	"karma/internal/trust"
)

func TestParseProcModules(t *testing.T) {
	rows := parseProcModules("binfmt_misc 24576 1 - Live 0x0000000000000000 (OE)\n" +
		"xt_conntrack 16384 2 nf_conntrack, Live 0x0000000000000000\n")
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Name != "binfmt_misc" || rows[0].Size != 24576 || rows[0].Used != 1 ||
		rows[0].State != "Live" || rows[0].Taint != "OE" {
		t.Errorf("first row = %+v", rows[0])
	}
	if rows[1].Taint != "" {
		t.Errorf("untainted module taint = %q", rows[1].Taint)
	}
}

func TestModuleNameAndDependencyMap(t *testing.T) {
	cases := map[string]string{
		"foo.ko":      "foo",
		"foo.ko.xz":   "foo",
		"foo-bar.ko":  "foo_bar",
		"foo.ko.zst":  "foo",
		"foo.txt":     "",
		"not-a-match": "",
	}
	for file, want := range cases {
		if got := moduleName(file); got != want {
			t.Errorf("moduleName(%q) = %q, want %q", file, got, want)
		}
	}
	mapping := parseModulesDep("kernel/fs/x.ko: kernel/dep.ko\nupdates/dkms/zz-probe.ko.zst:\n", "/lib/modules/7")
	if mapping["x"] != "/lib/modules/7/kernel/fs/x.ko" {
		t.Errorf("x = %q", mapping["x"])
	}
	if mapping["zz_probe"] != "/lib/modules/7/updates/dkms/zz-probe.ko.zst" {
		t.Errorf("zz_probe = %q", mapping["zz_probe"])
	}
}

func TestMergeModuleReads(t *testing.T) {
	first := []moduleRow{{Name: "a"}, {Name: "b"}}
	second := []moduleRow{{Name: "a"}, {Name: "c"}}
	loaded, order, stable := mergeModuleReads(
		moduleRead{rows: first, ok: true},
		moduleRead{rows: second, ok: true},
	)
	if len(loaded) != 3 || len(order) != 3 {
		t.Fatalf("loaded = %+v order = %v", loaded, order)
	}
	if !stable["a"] || stable["b"] || stable["c"] {
		t.Errorf("stable = %v, want only a", stable)
	}
}

func TestDiffModuleViews(t *testing.T) {
	stable := map[string]bool{"a": true, "b": true, "c": true}
	loaded := map[string]bool{"a": true, "b": true, "c": true}
	sysfs := map[string]bool{"a": true, "b": true, "hidden": true}
	symbols := map[string]bool{"a": true, "hidden2": true}
	hidden, gaps, _ := diffModuleViews(stable, loaded, sysfs, true, symbols, true)
	if len(hidden) != 2 || hidden[0].Name != "hidden" || hidden[1].Name != "hidden2" {
		t.Fatalf("hidden = %+v", hidden)
	}
	if len(gaps) != 1 || gaps[0] != "c" {
		t.Errorf("registry gaps = %v, want [c]", gaps)
	}
	hidden, gaps, _ = diffModuleViews(stable, loaded, nil, false, symbols, true)
	if len(hidden) != 1 || hidden[0].Name != "hidden2" || len(gaps) != 0 {
		t.Errorf("without sysfs: hidden = %+v gaps = %v", hidden, gaps)
	}
}

func TestDiffModuleViewsEmptySysfs(t *testing.T) {
	stable := map[string]bool{"a": true}
	loaded := map[string]bool{"a": true}
	hidden, gaps, coverage := diffModuleViews(stable, loaded, map[string]bool{}, true, map[string]bool{"a": true}, true)
	if len(hidden) != 0 || len(gaps) != 0 || len(coverage) == 0 {
		t.Errorf("empty sysfs: hidden = %+v gaps = %v coverage = %v", hidden, gaps, coverage)
	}
}

func TestDiffModuleViewsLoadingRace(t *testing.T) {
	// b appears only in the second /proc read: it loaded during collection and
	// must not read as hidden just because sysfs already carries it.
	stable := map[string]bool{"a": true}
	loaded := map[string]bool{"a": true, "b": true}
	sysfs := map[string]bool{"a": true, "b": true}
	hidden, gaps, _ := diffModuleViews(stable, loaded, sysfs, true, map[string]bool{"a": true}, true)
	if len(hidden) != 0 || len(gaps) != 0 {
		t.Errorf("loading race: hidden = %+v gaps = %v", hidden, gaps)
	}
}

func TestTaintDecode(t *testing.T) {
	mask := 1<<1 | 1<<3 | 1<<12
	names := taintNames(mask)
	for _, want := range []string{"forced module load", "forced module unload", "out-of-tree module"} {
		if !strings.Contains(strings.Join(names, ", "), want) {
			t.Errorf("taint names = %v, missing %q", names, want)
		}
	}
	finding, ok := taintFinding(&KernelState{Tainted: mask, TaintNames: names})
	if !ok || finding.Severity != High || !strings.Contains(finding.Detail, "forced module load") {
		t.Errorf("taint finding = %+v ok = %t", finding, ok)
	}
	if _, ok := taintFinding(&KernelState{Tainted: 1 << 12}); ok {
		t.Errorf("an out-of-tree-only taint produced a finding")
	}
}

func TestParseLdSoConf(t *testing.T) {
	includes, dirs := parseLdSoConf("# comment\n/usr/local/lib\n" +
		"include /etc/ld.so.conf.d/*.conf\nhwcap 1 nosegneg\nlib\n")
	if len(includes) != 1 || includes[0] != "/etc/ld.so.conf.d/*.conf" {
		t.Errorf("includes = %v", includes)
	}
	if len(dirs) != 2 || dirs[0] != "/usr/local/lib" || dirs[1] != "/etc/lib" {
		t.Errorf("dirs = %v", dirs)
	}
}

func TestParseModuleDeclarations(t *testing.T) {
	rows := parseModuleDeclarations("loop\n# comment\nfoo-bar options=1\n/sbin/modprobe bad\n\n")
	if len(rows) != 2 || rows[0].Name != "loop" || rows[0].Line != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[1].Name != "foo_bar" || rows[1].Line != 3 {
		t.Errorf("second row = %+v", rows[1])
	}
}

func TestJudgeHiddenKernelState(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{},
		Kernel: KernelState{
			Collected:  true,
			Hidden:     []HiddenModule{{Name: "diamorphine", Views: []string{"sysfs"}}},
			HiddenPIDs: []int{4242},
			Tainted:    1 << 1,
			TaintNames: taintNames(1 << 1),
		},
	}
	report := Judge(snapshot, Filter{})
	classes := map[string]Finding{}
	for _, finding := range report.Findings {
		classes[finding.Class] = finding
	}
	if finding, ok := classes["hidden-module"]; !ok || finding.Severity != Critical || finding.Reach != KernelAsset {
		t.Errorf("hidden module finding = %+v", finding)
	}
	if finding, ok := classes["hidden-process"]; !ok || finding.Severity != Critical {
		t.Errorf("hidden process finding = %+v", finding)
	}
	if finding, ok := classes["kernel-taint"]; !ok || finding.Severity != High {
		t.Errorf("taint finding = %+v", finding)
	}
}

func TestJudgeModuleFile(t *testing.T) {
	path := "/lib/modules/7.0/updates/zz-probe.ko"
	runtimeFacts := pathFacts(path, 1200, 0o644, 0)
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{path: runtimeFacts},
		Kernel: KernelState{Collected: true, Modules: []KernelModule{{
			Name: "zz_probe", File: path, FileState: ModuleFileMapped, Facts: runtimeFacts,
		}}},
	}
	report := Judge(snapshot, Filter{})
	var found bool
	for _, finding := range report.Findings {
		if finding.Class == "module-introduction" {
			found = true
			if finding.Severity != Critical || finding.Reach != KernelAsset {
				t.Errorf("module finding = %+v", finding)
			}
		}
	}
	if !found {
		t.Fatalf("findings = %+v, want module-introduction", report.Findings)
	}

	baseFacts := trust.Build(path, trust.Attrs{
		Kind: trust.File, Mode: 0o644, UID: 0, Real: path, CTime: 900,
		Package: "linux-modules-7.0", PackageKnown: true,
	})
	quiet := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{path: baseFacts},
		Kernel: KernelState{Collected: true, Modules: []KernelModule{{
			Name: "zz_probe", File: path, FileState: ModuleFileMapped, Facts: baseFacts,
		}}},
	}
	if report := Judge(quiet, Filter{}); len(report.Findings) != 0 {
		t.Errorf("base module findings = %+v", report.Findings)
	}
}

func TestJudgeModuleUnmapped(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{},
		Kernel: KernelState{Collected: true, Modules: []KernelModule{{
			Name: "zz_probe", FileState: ModuleFileUnmapped,
		}}},
	}
	report := Judge(snapshot, Filter{})
	if len(report.Findings) != 1 || report.Findings[0].Class != "module-unmapped" {
		t.Fatalf("findings = %+v", report.Findings)
	}
	scoped := Judge(snapshot, Filter{Paths: []string{"/tmp"}})
	if len(scoped.Findings) != 0 {
		t.Errorf("path scope judged a global module finding: %+v", scoped.Findings)
	}
	stale := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{},
		Kernel: KernelState{Collected: true, MappingStale: true, Modules: []KernelModule{{
			Name: "zz_probe", FileState: ModuleFileUnmapped,
		}}},
	}
	if report := Judge(stale, Filter{}); len(report.Findings) != 0 {
		t.Errorf("stale module mapping judged unmapped rows: %+v", report.Findings)
	}
}

func TestKernelModuleScopeMatchesResolvedPath(t *testing.T) {
	path := "/lib/modules/7.0/kernel/fs/zz.ko"
	real := "/usr/lib/modules/7.0/kernel/fs/zz.ko"
	facts := pathFacts(path, 1200, 0o644, 0)
	facts.Real = real
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{path: facts},
		Kernel: KernelState{Collected: true, Modules: []KernelModule{{
			Name: "zz", File: path, FileState: ModuleFileMapped, Facts: facts,
		}}},
	}
	report := Judge(snapshot, Filter{Paths: []string{"/usr/lib/modules"}})
	var found bool
	for _, finding := range report.Findings {
		if finding.Class == "module-introduction" {
			found = true
		}
	}
	if !found {
		t.Errorf("resolved module path did not match the scope: %+v", report.Findings)
	}
}

func TestKernelFindingsHonorPathScope(t *testing.T) {
	path := "/lib/modules/7.0/kernel/fs/zz.ko"
	facts := pathFacts(path, 1200, 0o644, 0)
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{path: facts},
		Kernel: KernelState{
			Collected:  true,
			Modules:    []KernelModule{{Name: "zz", File: path, FileState: ModuleFileMapped, Facts: facts}},
			Hidden:     []HiddenModule{{Name: "zz", Views: []string{"sysfs"}}},
			HiddenPIDs: []int{4242},
		},
	}
	report := Judge(snapshot, Filter{Paths: []string{"/opt"}})
	for _, finding := range report.Findings {
		if finding.Class == "module-introduction" || finding.Class == "hidden-module" || finding.Class == "hidden-process" {
			t.Errorf("path scope kept a kernel finding: %+v", finding)
		}
	}
	unit := Judge(snapshot, Filter{Units: map[string]bool{"ssh.service": true}})
	if len(unit.Findings) != 0 {
		t.Errorf("unit scope kept kernel findings: %+v", unit.Findings)
	}
}

func TestKernelConfigFindingsCiteTheirSources(t *testing.T) {
	loader := "/etc/ld.so.conf.d/zz-local.conf"
	declaration := "/etc/modules-load.d/zz.conf"
	loaderFacts := pathFacts(loader, 1200, 0o644, 0)
	declarationFacts := pathFacts(declaration, 1200, 0o644, 0)
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{loader: loaderFacts, declaration: declarationFacts},
		Kernel: KernelState{
			Collected:        true,
			LoaderConfig:     []string{loader},
			DeclarationFiles: []string{declaration},
			Sources: map[string]Quote{
				loader:      {Path: loader, Line: 2, Text: "/var/lib/vendor/runtime"},
				declaration: {Path: declaration, Line: 1, Text: "vendor_module"},
			},
		},
	}
	report := Judge(snapshot, Filter{})
	findings := map[string]Finding{}
	for _, finding := range report.Findings {
		findings[finding.Class] = finding
	}
	for class, want := range map[string]Quote{
		"loader-config":      snapshot.Kernel.Sources[loader],
		"module-declaration": snapshot.Kernel.Sources[declaration],
	} {
		finding, ok := findings[class]
		if !ok {
			t.Errorf("findings = %+v, want %s", report.Findings, class)
			continue
		}
		if len(finding.Quotes) != 1 || finding.Quotes[0] != want {
			t.Errorf("%s quotes = %+v, want %+v", class, finding.Quotes, want)
		}
	}
}
