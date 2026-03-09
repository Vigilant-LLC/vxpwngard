package autofix

import "strings"

// FixSecretsExposure extracts ${{ secrets.* }} and ${{ github.token }} expressions
// from run: blocks into env: variable mappings. Fixes RGS-008.
func FixSecretsExposure(dir string, dryRun bool) ([]FixResult, error) {
	matcher := func(expr string) bool {
		lower := strings.ToLower(expr)
		return strings.Contains(lower, "secrets.") || strings.Contains(lower, "github.token")
	}
	return ExtractExpressionsToEnv(dir, matcher, "RGS-008", dryRun)
}
