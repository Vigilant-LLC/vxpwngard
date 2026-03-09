package autofix

import "strings"

// tier1Sources are the untrusted GitHub context values that RGS-002 targets.
var tier1Sources = []string{
	"github.head_ref",
	"github.ref_name",
	"github.ref",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.sha",
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.discussion.body",
	"github.event.discussion.title",
}

// FixExpressionInjection extracts Tier-1 untrusted expressions from run: blocks
// into env: variable mappings. Fixes RGS-002.
func FixExpressionInjection(dir string, dryRun bool) ([]FixResult, error) {
	matcher := func(expr string) bool {
		lower := strings.ToLower(expr)
		for _, src := range tier1Sources {
			if strings.Contains(lower, strings.ToLower(src)) {
				return true
			}
		}
		return false
	}
	return ExtractExpressionsToEnv(dir, matcher, "RGS-002", dryRun)
}
