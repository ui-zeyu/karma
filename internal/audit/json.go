package audit

// The JSON contract: one shape per fact, stated once, shared by every
// machine-readable answer. The text report and the graphs encode their
// findings and boundaries through these types, so a field the report gains
// reaches every consumer the same way.

import (
	"encoding/json"
	"io"
	"time"
)

type boundaryData struct {
	Time       string `json:"time,omitempty"`
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
}

type findingData struct {
	Class    string   `json:"class"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Path     string   `json:"path"`
	Origin   string   `json:"origin"`
	Reach    string   `json:"reach"`
	Detail   string   `json:"detail,omitempty"`
	Chain    []string `json:"chain,omitempty"`
	Nodes    []string `json:"nodes,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
	Quotes   []Quote  `json:"quotes,omitempty"`
}

func boundaryDataOf(boundary Boundary) boundaryData {
	out := boundaryData{
		Kind:       boundary.Kind,
		Source:     boundary.Source,
		Confidence: boundary.Confidence.String(),
	}
	if !boundary.Time.IsZero() {
		out.Time = boundary.Time.Format(time.RFC3339)
	}
	return out
}

func findingDataOf(finding Finding) findingData {
	return findingData{
		Class:    finding.Class,
		Severity: finding.Severity.String(),
		Title:    finding.Title,
		Path:     finding.Path,
		Origin:   finding.Origin.String(),
		Reach:    finding.Reach.String(),
		Detail:   finding.Detail,
		Chain:    traceTexts(finding.Trace),
		Nodes:    traceNodes(finding.Trace),
		Evidence: finding.Evidence,
		Quotes:   finding.Quotes,
	}
}

// encode writes one JSON document, indented the way every karma answer is.
func encode(w io.Writer, document any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

// WriteJSON writes the report as one object: the findings and the summary
// inventories a machine answer carries. The raw inventories a section of
// `karma show --json` names are the typed way to read them.
func WriteJSON(w io.Writer, report *Report) error {
	out := struct {
		Source      string         `json:"source"`
		Host        Host           `json:"host"`
		Boundary    boundaryData   `json:"boundary"`
		OffDomains  []string       `json:"off_domains,omitempty"`
		Findings    []findingData  `json:"findings"`
		Services    []Service      `json:"services,omitempty"`
		Listeners   []Socket       `json:"listeners,omitempty"`
		Connections []Connection   `json:"connections,omitempty"`
		Mounts      []Mount        `json:"mounts,omitempty"`
		Ledger      *LedgerSummary `json:"ledger,omitempty"`
		Kernel      *KernelState   `json:"kernel,omitempty"`
		Coverage    []string       `json:"coverage,omitempty"`
	}{
		Source:      report.Source,
		Host:        report.Host,
		Boundary:    boundaryDataOf(report.Boundary),
		OffDomains:  report.OffDomains,
		Findings:    make([]findingData, 0, len(report.Findings)),
		Services:    report.Services,
		Listeners:   report.Sockets,
		Connections: report.Connections,
		Mounts:      report.Mounts,
		Kernel:      report.Kernel,
		Coverage:    report.Coverage,
	}
	if report.Ledger.Kind != "" && report.Ledger.Kind != "none" {
		ledger := report.Ledger
		out.Ledger = &ledger
	}
	for _, finding := range report.Findings {
		out.Findings = append(out.Findings, findingDataOf(finding))
	}
	return encode(w, out)
}
