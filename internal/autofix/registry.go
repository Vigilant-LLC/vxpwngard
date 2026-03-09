package autofix

// FixFunc applies an auto-fix for a specific rule to all workflow files in dir.
type FixFunc func(dir string, dryRun bool) ([]FixResult, error)

// Registry maps rule IDs to their auto-fix functions.
// Only rules with auto-fix capability are included.
var Registry = map[string]FixFunc{
	"RGS-002": FixExpressionInjection,
	"RGS-007": fixRGS007Pin,
	"RGS-008": FixSecretsExposure,
	"RGS-014": FixDispatchInputInjection,
	"RGS-015": FixDebugEnvVars,
}

// fixRGS007Pin wraps PinActions to conform to the FixFunc signature.
func fixRGS007Pin(dir string, dryRun bool) ([]FixResult, error) {
	pinResults, err := PinActions(dir, dryRun)
	if err != nil {
		return nil, err
	}

	var results []FixResult
	for _, r := range pinResults {
		detail := r.Action + "@" + r.OldRef
		if r.NewRef != "" {
			detail += " → " + r.NewRef[:minInt(12, len(r.NewRef))] + "..."
		}
		results = append(results, FixResult{
			File:    r.File,
			RuleID:  "RGS-007",
			Detail:  detail,
			LineNum: r.LineNum,
			Error:   r.Error,
		})
	}
	return results, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
