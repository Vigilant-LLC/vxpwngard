package reporter

import (
	"encoding/json"
	"io"

	"github.com/Vigilant-LLC/vxpwngard/internal/rules"
)

// jsonReport is the top-level structure for JSON output.
type jsonReport struct {
	Findings []rules.Finding  `json:"findings"`
	Summary  *findingSummary  `json:"summary"`
}

// findingSummary provides severity counts for the scan.
type findingSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// ReportJSON writes findings as a structured JSON object to the provided
// writer. The output contains a "findings" array and a "summary" object
// with severity counts.
func ReportJSON(w io.Writer, findings []rules.Finding) error {
	if findings == nil {
		findings = []rules.Finding{}
	}

	summary := &findingSummary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
	}

	report := jsonReport{
		Findings: findings,
		Summary:  summary,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	return enc.Encode(report)
}
