package taint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Vigilant-LLC/runner-guard/internal/parser"
)

// Tier1Sources contains fully attacker-controlled expression fragments.
// These are GitHub Actions context values that an external attacker can set
// directly through pull request metadata, issue content, or comments.
var Tier1Sources = []string{
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

// Tier2Sources represents fork execution context. These are synthetic markers
// used when pull_request_target checks out and executes fork code.
var Tier2Sources = []string{
	"FORK_CODE_EXECUTION",
}

// Tier3Sources represents AI configuration injection sources. These are
// synthetic markers used when fork code containing AI config files
// (CLAUDE.md, copilot-instructions.md, etc.) is checked out and processed.
var Tier3Sources = []string{
	"AI_CONFIG_FROM_FORK",
}

// ShellSinkPatterns are compiled regular expressions that detect GitHub Actions
// expression interpolation inside run: blocks — the primary injection sink.
var ShellSinkPatterns []*regexp.Regexp

// shellSinkPatternStrings are the raw patterns before compilation.
var shellSinkPatternStrings = []string{
	`\$\{\{[^}]+\}\}`, // any expression interpolated directly into run:
}

// DangerousShellPatterns are compiled regular expressions that match inherently
// dangerous shell constructs regardless of taint status.
var DangerousShellPatterns []*regexp.Regexp

// dangerousShellPatternStrings are the raw patterns with human-readable descriptions.
var dangerousShellPatternDescriptions = []struct {
	pattern     string
	description string
}{
	{`curl\s+[^\|]+\|\s*(ba)?sh`, "curl piped to shell"},
	{`wget\s+[^\|]+\|\s*(ba)?sh`, "wget piped to shell"},
	{`eval\s+\$`, "eval with variable expansion"},
	{`bash\s+-c\s+["']?\$`, "bash -c with variable expansion"},
}

// PublishingSinks contains strings that indicate a step performs package
// publishing or release creation — high-value targets for supply chain attacks.
var PublishingSinks = []string{
	"npm publish",
	"docker push",
	"gh release",
	"vsce publish",
	"cargo publish",
	"gem push",
	"twine upload",
	"actions/create-release",
}

// secretExprPattern matches ${{ secrets.* }} expressions.
var secretExprPattern *regexp.Regexp

// expressionPattern matches ${{ ... }} expression syntax used by GitHub Actions.
var expressionPattern *regexp.Regexp

func init() {
	// Compile shell sink patterns.
	ShellSinkPatterns = make([]*regexp.Regexp, 0, len(shellSinkPatternStrings))
	for _, p := range shellSinkPatternStrings {
		ShellSinkPatterns = append(ShellSinkPatterns, regexp.MustCompile(p))
	}

	// Compile dangerous shell patterns.
	DangerousShellPatterns = make([]*regexp.Regexp, 0, len(dangerousShellPatternDescriptions))
	for _, entry := range dangerousShellPatternDescriptions {
		DangerousShellPatterns = append(DangerousShellPatterns, regexp.MustCompile(`(?i)`+entry.pattern))
	}

	// Compile secret expression pattern.
	secretExprPattern = regexp.MustCompile(`(?i)\$\{\{\s*secrets\.[^}]+\}\}`)

	// Compile expression pattern for stripping ${{ ... }} blocks before
	// searching for shell env var references.
	expressionPattern = regexp.MustCompile(`\$\{\{[^}]+\}\}`)
}

// IsTainted checks whether a ${{ }} expression string contains any of the
// given taint source substrings. The comparison is case-insensitive to handle
// variations in expression casing.
func IsTainted(expr string, sources []string) bool {
	lower := strings.ToLower(expr)
	for _, src := range sources {
		if strings.Contains(lower, strings.ToLower(src)) {
			return true
		}
	}
	return false
}

// ExtractTaintedExpressions examines a step's Expressions list and returns
// all expressions that contain at least one taint source substring.
func ExtractTaintedExpressions(step *parser.Step, sources []string) []string {
	if step == nil {
		return nil
	}

	var tainted []string
	for _, expr := range step.Expressions {
		if IsTainted(expr, sources) {
			tainted = append(tainted, expr)
		}
	}
	return tainted
}

// HasDangerousSink checks a run: block for inherently dangerous shell patterns
// such as curl|bash, wget|sh, eval, or bash -c constructs. Returns whether a
// match was found and a human-readable description of the matched pattern.
func HasDangerousSink(run string) (bool, string) {
	if run == "" {
		return false, ""
	}

	for i, re := range DangerousShellPatterns {
		if re.MatchString(run) {
			return true, dangerousShellPatternDescriptions[i].description
		}
	}
	return false, ""
}

// IsEnvTaintPropagated detects taint propagation through environment variables.
// This occurs when:
//  1. A job-level or step-level env variable is set to a tainted expression, AND
//  2. A run: block in that job references the env variable via $ENV_VAR or ${ENV_VAR}
//
// Returns a list of descriptions identifying the propagation paths found.
func IsEnvTaintPropagated(job *parser.Job) []string {
	if job == nil {
		return nil
	}

	var propagations []string

	// Collect tainted env vars from job level.
	taintedEnvVars := make(map[string]string) // env var name -> tainted expression
	for envName, envValue := range job.Env {
		if IsTainted(envValue, Tier1Sources) {
			taintedEnvVars[envName] = envValue
		}
	}

	// Also collect tainted env vars from step level and check run blocks.
	for _, step := range job.Steps {
		// Collect step-level tainted env vars.
		stepTaintedVars := make(map[string]string)
		for k, v := range taintedEnvVars {
			stepTaintedVars[k] = v
		}
		for envName, envValue := range step.Env {
			if IsTainted(envValue, Tier1Sources) {
				stepTaintedVars[envName] = envValue
			}
		}

		// Check if the run block references any tainted env var.
		if step.Run == "" {
			continue
		}

		for envName, taintExpr := range stepTaintedVars {
			if envVarIsReferenced(step.Run, envName) {
				propagations = append(propagations, fmt.Sprintf(
					"env var %s (set to %s) is used in run block of step %q",
					envName, taintExpr, stepIdentifier(step),
				))
			}
		}
	}

	return propagations
}

// envVarIsReferenced checks whether a shell script references a given
// environment variable by name, using $VAR or ${VAR} syntax. It avoids
// false positives from ${{ }} GitHub Actions expressions.
func envVarIsReferenced(run string, envName string) bool {
	// Look for $ENV_NAME or ${ENV_NAME} patterns.
	// We need to be careful not to match inside ${{ }} expressions.

	// First, strip out all ${{ ... }} expressions to avoid false positives.
	stripped := expressionPattern.ReplaceAllString(run, "")

	// Now search for $ENV_NAME or ${ENV_NAME} in the stripped text.
	// Match $ENV_NAME (not followed by another word char that would make it a different var).
	directPattern := regexp.MustCompile(`\$` + regexp.QuoteMeta(envName) + `(?:[^A-Za-z0-9_]|$)`)
	if directPattern.MatchString(stripped) {
		return true
	}

	// Match ${ENV_NAME}.
	bracedPattern := regexp.MustCompile(`\$\{` + regexp.QuoteMeta(envName) + `\}`)
	if bracedPattern.MatchString(stripped) {
		return true
	}

	return false
}

// stepIdentifier returns a human-readable identifier for a step, preferring
// Name, then ID, then a fallback.
func stepIdentifier(step *parser.Step) string {
	if step.Name != "" {
		return step.Name
	}
	if step.ID != "" {
		return step.ID
	}
	return fmt.Sprintf("line %d", step.LineNumber)
}

// ContainsPublishingSink checks if a run: command string or uses: action
// reference contains any publishing indicator. This identifies steps that
// perform package publishing or release creation.
func ContainsPublishingSink(run string, uses string) bool {
	combined := strings.ToLower(run + " " + uses)
	for _, sink := range PublishingSinks {
		if strings.Contains(combined, strings.ToLower(sink)) {
			return true
		}
	}
	return false
}

// HasSecretAccess checks whether a step or its parent job has access to
// secrets. This is determined by:
//   - The step's expressions containing secrets.* references
//   - The step's env values containing secrets.* references
//   - The job's env values containing secrets.* references
//   - The job's Secrets list being non-empty
func HasSecretAccess(step *parser.Step, job *parser.Job) bool {
	if step != nil {
		// Check step expressions for secret references.
		for _, expr := range step.Expressions {
			if secretExprPattern.MatchString(expr) {
				return true
			}
		}

		// Check step env values for secret references.
		for _, v := range step.Env {
			if secretExprPattern.MatchString(v) {
				return true
			}
		}
	}

	if job != nil {
		// Check job env values for secret references.
		for _, v := range job.Env {
			if secretExprPattern.MatchString(v) {
				return true
			}
		}

		// Check job-level secrets list.
		if len(job.Secrets) > 0 {
			return true
		}
	}

	return false
}
