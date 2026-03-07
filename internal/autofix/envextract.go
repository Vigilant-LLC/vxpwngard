package autofix

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// FixResult describes a single auto-fix applied to a file.
type FixResult struct {
	File    string
	RuleID  string
	Detail  string
	LineNum int
	Error   string
}

// fixExprRe matches ${{ ... }} expressions in run blocks.
var fixExprRe = regexp.MustCompile(`\$\{\{[^}]+\}\}`)

// runKeyRe matches a "run:" key in a YAML line.
var runKeyRe = regexp.MustCompile(`^(\s*-?\s*)run:\s*(.*)$`)

// ExpressionMatcher returns true for expressions that should be extracted to env vars.
type ExpressionMatcher func(expr string) bool

// knownEnvNames maps common GitHub context paths to readable env var names.
var knownEnvNames = map[string]string{
	"github.head_ref":                    "HEAD_REF",
	"github.ref_name":                    "REF_NAME",
	"github.ref":                         "GIT_REF",
	"github.event.pull_request.head.ref": "PR_HEAD_REF",
	"github.event.pull_request.head.sha": "PR_HEAD_SHA",
	"github.event.pull_request.title":    "PR_TITLE",
	"github.event.pull_request.body":     "PR_BODY",
	"github.event.issue.title":           "ISSUE_TITLE",
	"github.event.issue.body":            "ISSUE_BODY",
	"github.event.comment.body":          "COMMENT_BODY",
	"github.event.review.body":           "REVIEW_BODY",
	"github.event.review_comment.body":   "REVIEW_COMMENT_BODY",
	"github.event.discussion.body":       "DISCUSSION_BODY",
	"github.event.discussion.title":      "DISCUSSION_TITLE",
}

// ExtractExpressionsToEnv processes workflow files in the given directory,
// extracting matching ${{ }} expressions from run: blocks into env: mappings.
func ExtractExpressionsToEnv(dir string, matcher ExpressionMatcher, ruleID string, dryRun bool) ([]FixResult, error) {
	workflowDir := filepath.Join(dir, ".github", "workflows")
	info, err := os.Stat(workflowDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("autofix: stat %s: %w", workflowDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("autofix: %s is not a directory", workflowDir)
	}

	var results []FixResult
	walkErr := filepath.WalkDir(workflowDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		fileResults, processErr := processFileEnvExtract(path, matcher, ruleID, dryRun)
		if processErr != nil {
			return processErr
		}
		results = append(results, fileResults...)
		return nil
	})
	return results, walkErr
}

// processFileEnvExtract handles a single workflow file, extracting matching
// expressions from run: blocks into env: variable mappings.
func processFileEnvExtract(path string, matcher ExpressionMatcher, ruleID string, dryRun bool) ([]FixResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	var results []FixResult
	modified := false

	i := 0
	for i < len(lines) {
		// Look for "run:" key.
		m := runKeyRe.FindStringSubmatch(lines[i])
		if m == nil {
			i++
			continue
		}

		prefix := m[1] // indentation + optional "- "
		afterRun := strings.TrimSpace(m[2])

		// Determine property indentation level.
		propIndent := computePropIndent(prefix)

		// Parse run block boundaries.
		contentStart, contentEnd, isMulti := parseRunBounds(lines, i, afterRun, propIndent)
		if contentStart < 0 {
			i++
			continue
		}

		// Collect run content and find matching expressions.
		runContent := collectRunContent(lines, i, contentStart, contentEnd, isMulti, afterRun)
		exprs := fixExprRe.FindAllString(runContent, -1)

		var matchingExprs []string
		seen := make(map[string]bool)
		for _, expr := range exprs {
			if !seen[expr] && matcher(expr) {
				matchingExprs = append(matchingExprs, expr)
				seen[expr] = true
			}
		}

		if len(matchingExprs) == 0 {
			i = contentEnd + 1
			continue
		}

		// Generate env var names.
		type envEntry struct {
			name string
			expr string
		}
		var entries []envEntry
		usedNames := make(map[string]bool)

		for _, expr := range matchingExprs {
			contextPath := extractContextPath(expr)
			envName := deriveEnvVarName(contextPath)
			base := envName
			counter := 2
			for usedNames[envName] {
				envName = fmt.Sprintf("%s_%d", base, counter)
				counter++
			}
			usedNames[envName] = true
			entries = append(entries, envEntry{name: envName, expr: expr})
		}

		// Replace expressions in run content with env var references.
		for _, entry := range entries {
			if isMulti {
				for j := contentStart; j <= contentEnd; j++ {
					lines[j] = strings.ReplaceAll(lines[j], entry.expr, "${"+entry.name+"}")
				}
			} else {
				lines[i] = strings.ReplaceAll(lines[i], entry.expr, "${"+entry.name+"}")
			}
		}

		// Find or create env: block for this step.
		dashIndent := propIndent - 2
		stepStart := findStepStart(lines, i, dashIndent)
		stepEnd := findStepEnd(lines, i, dashIndent)
		existingEnvLine := findExistingEnvInStep(lines, stepStart, stepEnd, propIndent)

		insertedCount := 0
		if existingEnvLine >= 0 {
			envContentEnd := findEnvContentEnd(lines, existingEnvLine, propIndent)
			envContentIndent := strings.Repeat(" ", propIndent+2)
			var newEnvLines []string
			for _, entry := range entries {
				newEnvLines = append(newEnvLines, envContentIndent+entry.name+": "+entry.expr)
			}
			insertIdx := envContentEnd + 1
			lines = insertLines(lines, insertIdx, newEnvLines)
			insertedCount = len(newEnvLines)
		} else {
			envKeyIndent := strings.Repeat(" ", propIndent)
			envContentIndent := strings.Repeat(" ", propIndent+2)
			var newLines []string
			newLines = append(newLines, envKeyIndent+"env:")
			for _, entry := range entries {
				newLines = append(newLines, envContentIndent+entry.name+": "+entry.expr)
			}
			insertIdx := contentEnd + 1
			lines = insertLines(lines, insertIdx, newLines)
			insertedCount = len(newLines)
		}

		modified = true
		for _, entry := range entries {
			results = append(results, FixResult{
				File:    path,
				RuleID:  ruleID,
				Detail:  fmt.Sprintf("Extracted %s to env var %s", entry.expr, entry.name),
				LineNum: i + 1,
			})
		}

		i = contentEnd + 1 + insertedCount
	}

	if modified && !dryRun {
		newContent := strings.Join(lines, "\n")
		if writeErr := os.WriteFile(path, []byte(newContent), 0644); writeErr != nil {
			return results, fmt.Errorf("writing %s: %w", path, writeErr)
		}
	}

	return results, nil
}

// computePropIndent returns the property indentation from the run: line prefix.
// If the prefix includes "- ", the property indent is dash indent + 2.
func computePropIndent(prefix string) int {
	trimmed := strings.TrimRight(prefix, " \t")
	if strings.HasSuffix(trimmed, "-") {
		// "    - " → dash at len("    "), prop at len("    ") + 2
		dashIndent := len(strings.TrimRight(trimmed, "-"))
		return dashIndent + 2
	}
	return len(prefix) - len(strings.TrimLeft(prefix, " \t"))
}

// parseRunBounds returns the start and end line indices of run block content.
// Returns -1, -1, false if no content is found.
func parseRunBounds(lines []string, keyLine int, afterRun string, propIndent int) (int, int, bool) {
	// Multi-line block scalars: |, >, |-, >-, |+, >+
	if afterRun == "|" || afterRun == ">" || afterRun == "|-" || afterRun == ">-" || afterRun == "|+" || afterRun == ">+" {
		start := keyLine + 1
		end := start
		for end < len(lines) {
			if strings.TrimSpace(lines[end]) == "" {
				end++
				continue
			}
			if countIndent(lines[end]) <= propIndent {
				break
			}
			end++
		}
		end--
		if end < start {
			return -1, -1, false
		}
		return start, end, true
	}

	// Single-line: content on same line as run:
	if afterRun != "" {
		return keyLine, keyLine, false
	}

	return -1, -1, false
}

// collectRunContent joins the run content lines into a single string.
func collectRunContent(lines []string, keyLine, contentStart, contentEnd int, isMulti bool, afterRun string) string {
	if isMulti {
		var parts []string
		for j := contentStart; j <= contentEnd; j++ {
			parts = append(parts, lines[j])
		}
		return strings.Join(parts, "\n")
	}
	return afterRun
}

// findStepStart scans backward to find the line where the current step begins.
func findStepStart(lines []string, fromLine int, dashIndent int) int {
	for j := fromLine; j >= 0; j-- {
		line := lines[j]
		if strings.TrimSpace(line) == "" {
			continue
		}
		ci := countIndent(line)
		if ci == dashIndent {
			trimmed := strings.TrimLeft(line, " \t")
			if len(trimmed) > 0 && trimmed[0] == '-' {
				return j
			}
		}
		if ci < dashIndent {
			return fromLine
		}
	}
	return 0
}

// findStepEnd returns the index of the first line after the current step.
func findStepEnd(lines []string, fromLine int, dashIndent int) int {
	for j := fromLine + 1; j < len(lines); j++ {
		line := lines[j]
		if strings.TrimSpace(line) == "" {
			continue
		}
		if countIndent(line) <= dashIndent {
			return j
		}
	}
	return len(lines)
}

// findExistingEnvInStep looks for an existing env: key within a step.
func findExistingEnvInStep(lines []string, stepStart, stepEnd, propIndent int) int {
	for j := stepStart; j < stepEnd; j++ {
		line := lines[j]
		if strings.TrimSpace(line) == "" {
			continue
		}
		ci := countIndent(line)
		trimmed := strings.TrimSpace(line)
		if ci == propIndent && trimmed == "env:" {
			return j
		}
		// Handle "- env:" on the step start line (rare but valid)
		if strings.HasSuffix(strings.TrimSpace(strings.TrimLeft(line, " \t-")), "env:") && ci < propIndent {
			continue // skip — this is the step dash line with a different key
		}
	}
	return -1
}

// findEnvContentEnd returns the last line of env block content.
func findEnvContentEnd(lines []string, envKeyLine, propIndent int) int {
	envContentIndent := propIndent + 2
	last := envKeyLine
	for j := envKeyLine + 1; j < len(lines); j++ {
		line := lines[j]
		if strings.TrimSpace(line) == "" {
			continue
		}
		if countIndent(line) < envContentIndent {
			break
		}
		last = j
	}
	return last
}

// insertLines inserts new lines at the given index in the slice.
func insertLines(lines []string, idx int, newLines []string) []string {
	result := make([]string, 0, len(lines)+len(newLines))
	result = append(result, lines[:idx]...)
	result = append(result, newLines...)
	result = append(result, lines[idx:]...)
	return result
}

// countIndent returns the number of leading whitespace characters.
func countIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

// extractContextPath strips ${{ and }} from an expression, returning the inner path.
func extractContextPath(expr string) string {
	inner := strings.TrimSpace(expr)
	inner = strings.TrimPrefix(inner, "${{")
	inner = strings.TrimSuffix(inner, "}}")
	return strings.TrimSpace(inner)
}

// deriveEnvVarName generates a shell-safe environment variable name from a
// GitHub Actions context path.
func deriveEnvVarName(contextPath string) string {
	lower := strings.ToLower(contextPath)

	if name, ok := knownEnvNames[lower]; ok {
		return name
	}

	// secrets.FOO → FOO
	if strings.HasPrefix(lower, "secrets.") {
		return strings.ToUpper(sanitizeEnvName(contextPath[len("secrets."):]))
	}

	// github.token → GITHUB_TOKEN
	if lower == "github.token" {
		return "GITHUB_TOKEN"
	}

	// github.event.inputs.foo → INPUT_FOO
	if strings.HasPrefix(lower, "github.event.inputs.") {
		return "INPUT_" + strings.ToUpper(sanitizeEnvName(contextPath[len("github.event.inputs."):]))
	}

	// Fallback: last 2 path segments, uppercased.
	parts := strings.Split(contextPath, ".")
	if len(parts) >= 2 {
		last2 := parts[len(parts)-2] + "_" + parts[len(parts)-1]
		return strings.ToUpper(sanitizeEnvName(last2))
	}

	return strings.ToUpper(sanitizeEnvName(contextPath))
}

// sanitizeEnvName replaces non-alphanumeric characters with underscores.
func sanitizeEnvName(s string) string {
	var buf strings.Builder
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			buf.WriteRune(c)
		} else {
			buf.WriteRune('_')
		}
	}
	result := buf.String()
	if len(result) > 0 && result[0] >= '0' && result[0] <= '9' {
		result = "_" + result
	}
	return result
}
