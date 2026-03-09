package reporter

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/Vigilant-LLC/runner-guard/internal/rules"
)

// ---------- SARIF 2.1.0 types ----------

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name"`
	ShortDescription     sarifMessage              `json:"shortDescription"`
	FullDescription      sarifMessage              `json:"fullDescription"`
	HelpURI              string                    `json:"helpUri,omitempty"`
	DefaultConfiguration sarifDefaultConfiguration `json:"defaultConfiguration"`
	Properties           sarifRuleProperties       `json:"properties"`
}

type sarifDefaultConfiguration struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string             `json:"ruleId"`
	RuleIndex  int                `json:"ruleIndex"`
	Level      string             `json:"level"`
	Message    sarifMessage       `json:"message"`
	Locations  []sarifLocation    `json:"locations"`
	Properties sarifResultProperties `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifResultProperties struct {
	Severity string `json:"severity"`
	Evidence string `json:"evidence,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

// ---------- Public API ----------

// ReportSARIF writes findings as a valid SARIF 2.1.0 JSON document to the
// provided writer.
func ReportSARIF(w io.Writer, findings []rules.Finding) error {
	// Build a de-duplicated rules array keyed by RuleID and track each
	// rule's index so results can reference it.
	ruleIndex := map[string]int{}
	var sarifRules []sarifRule

	for _, f := range findings {
		if _, exists := ruleIndex[f.RuleID]; exists {
			continue
		}
		idx := len(sarifRules)
		ruleIndex[f.RuleID] = idx

		helpURI := ""
		if len(f.References) > 0 {
			helpURI = f.References[0]
		}

		sarifRules = append(sarifRules, sarifRule{
			ID:   f.RuleID,
			Name: f.RuleName,
			ShortDescription: sarifMessage{
				Text: f.RuleName,
			},
			FullDescription: sarifMessage{
				Text: f.Description,
			},
			HelpURI: helpURI,
			DefaultConfiguration: sarifDefaultConfiguration{
				Level: mapSeverity(f.Severity),
			},
			Properties: sarifRuleProperties{
				Tags: buildTags(f),
			},
		})
	}

	// Ensure the rules slice is never nil so it serialises as [].
	if sarifRules == nil {
		sarifRules = []sarifRule{}
	}

	// Build results.
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		line := f.LineNumber
		if line < 1 {
			line = 1
		}

		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex[f.RuleID],
			Level:     mapSeverity(f.Severity),
			Message: sarifMessage{
				Text: buildMessage(f),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.File,
						},
						Region: sarifRegion{
							StartLine: line,
						},
					},
				},
			},
			Properties: sarifResultProperties{
				Severity: f.Severity,
				Evidence: f.Evidence,
				Fix:      f.Fix,
			},
		})
	}

	doc := sarifDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "runner-guard",
						Version:        "0.1.0",
						InformationURI: "https://github.com/Vigilant-LLC/runner-guard",
						Rules:          sarifRules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	return enc.Encode(doc)
}

// ---------- helpers ----------

// mapSeverity converts the internal severity labels to SARIF result levels.
func mapSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "none"
	}
}

// buildMessage produces a human-readable one-liner for a SARIF result.
func buildMessage(f rules.Finding) string {
	msg := f.RuleName
	if f.Description != "" {
		msg += ": " + f.Description
	}
	if f.AttackScenario != "" {
		msg += " | Attack: " + f.AttackScenario
	}
	return msg
}

// buildTags returns tag strings suitable for SARIF rule properties.
func buildTags(f rules.Finding) []string {
	tags := []string{"security"}
	sev := strings.ToLower(f.Severity)
	if sev != "" {
		tags = append(tags, sev)
	}
	return tags
}
