package audit

// The machine answer carries the same source a reader sees: a finding's
// quotes and an activation edge's raw trigger line.

import (
	"bytes"
	"encoding/json"
	"testing"

	"karma/internal/startup"
)

func TestJSONCarriesFindingQuotes(t *testing.T) {
	report := &Report{Findings: []Finding{{
		Class: "web-script", Severity: Critical, Title: "web-root script",
		Path: "/var/www/html/shell.php", Origin: Runtime, Reach: ServiceAsset,
		Quotes: []Quote{{Path: "/var/www/html/shell.php", Line: 1, Text: "<?php system($_GET['c']); ?>"}},
	}}}
	var out bytes.Buffer
	if err := WriteJSON(&out, report); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			Quotes []Quote `json:"quotes"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 || len(doc.Findings[0].Quotes) != 1 {
		t.Fatalf("quotes = %+v", doc.Findings)
	}
	quote := doc.Findings[0].Quotes[0]
	if quote.Path != "/var/www/html/shell.php" || quote.Line != 1 || quote.Text != "<?php system($_GET['c']); ?>" {
		t.Errorf("quote = %+v", quote)
	}
}

func TestShowActivationJSONCarriesTheEdgeSource(t *testing.T) {
	trigger := "/etc/profile.d/vendor.sh"
	target := "/var/lib/vendor/.loader.sh"
	snapshot := &Snapshot{
		Boundary: boundary(),
		Activations: []startup.Edge{{
			Surface: startup.SurfaceProfile, Phase: startup.Login,
			Subject: startup.Subject{Class: startup.AccountRoot},
			Trigger: trigger, Line: 2, Source: "export VENDOR_LOADER=" + target,
			Target: target, Kind: startup.Source,
			TriggerFacts: pathFacts(trigger, 1200, 0o644, 0),
			TargetFacts:  pathFacts(target, 1200, 0o755, 0),
		}},
	}
	view := NewView(snapshot, Filter{})
	section, ok := SectionFor("activation")
	if !ok {
		t.Fatal("the activation section is missing from the table")
	}
	var out bytes.Buffer
	if err := WriteShowJSON(&out, view, section, "activation", RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Activations []struct {
			Source string `json:"source"`
		} `json:"activations"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Activations) != 1 || doc.Activations[0].Source != "export VENDOR_LOADER="+target {
		t.Errorf("activations = %+v", doc.Activations)
	}
}
