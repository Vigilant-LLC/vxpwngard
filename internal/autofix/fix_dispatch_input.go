package autofix

import "strings"

// FixDispatchInputInjection extracts ${{ github.event.inputs.* }} expressions
// from run: blocks into env: variable mappings. Fixes RGS-014.
func FixDispatchInputInjection(dir string, dryRun bool) ([]FixResult, error) {
	matcher := func(expr string) bool {
		return strings.Contains(strings.ToLower(expr), "github.event.inputs.")
	}
	return ExtractExpressionsToEnv(dir, matcher, "RGS-014", dryRun)
}
