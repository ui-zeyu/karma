package startup

import (
	"testing"

	"karma/internal/trust"
)

func TestAnalyzeStatesTheEdgeAndBothEndsFacts(t *testing.T) {
	unit := "/etc/systemd/system/agent.service"
	body := "[Service]\nUser=alice\nExecStart=/opt/agent --sync\n"
	facts := func(path string) trust.Facts {
		return trust.Build(path, trust.Attrs{
			Kind: trust.File, Mode: 0o755, UID: 0, Real: path,
			CTime: 1200, PackageKnown: true,
		})
	}
	corpus := NewCorpus([]File{{
		Path: unit, Unit: "agent.service", Surface: SurfaceSystemd, Dialect: UnitDialect, Body: body,
	}}, nil, facts)
	edges := Analyze(corpus)
	if len(edges) != 1 {
		t.Fatalf("edges = %+v, want one", edges)
	}
	edge := edges[0]
	if edge.Trigger != unit || edge.Target != "/opt/agent" || edge.Kind != Exec {
		t.Errorf("edge = %+v", edge)
	}
	if edge.Subject != Account("alice") || edge.Phase != BootStaged {
		t.Errorf("account = %q phase = %s", edge.Subject, edge.Phase)
	}
	if edge.TriggerFacts.Kind != trust.File || edge.TargetFacts.Kind != trust.File {
		t.Errorf("facts = trigger %+v target %+v", edge.TriggerFacts, edge.TargetFacts)
	}
}

func TestAnalyzeKeepsTheDynamicTargetAsCoverage(t *testing.T) {
	unit := "/etc/systemd/system/dynamic.service"
	corpus := NewCorpus([]File{{
		Path: unit, Unit: "dynamic.service", Surface: SurfaceSystemd, Dialect: UnitDialect,
		Body: "[Service]\nExecStart=$BIN --serve\n",
	}}, nil, func(path string) trust.Facts { return trust.Facts{Path: path, Kind: trust.Missing} })
	edges := Analyze(corpus)
	if len(edges) != 1 || !edges[0].Dynamic {
		t.Fatalf("edges = %+v, want one dynamic edge", edges)
	}
}
