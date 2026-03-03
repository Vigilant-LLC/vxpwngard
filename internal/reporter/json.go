package reporter

import (
	"encoding/json"
	"io"

	"github.com/Vigilant-LLC/vxpwngard/internal/rules"
)

// ReportJSON writes findings as a pretty-printed JSON array to the
// provided writer. All fields from the Finding struct are included.
func ReportJSON(w io.Writer, findings []rules.Finding) error {
	// Ensure we always emit an array, even when there are no findings.
	if findings == nil {
		findings = []rules.Finding{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	return enc.Encode(findings)
}
