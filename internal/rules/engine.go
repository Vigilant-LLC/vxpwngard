package rules

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/Vigilant-LLC/runner-guard/internal/parser"
	"github.com/Vigilant-LLC/runner-guard/internal/taint"
)

// Finding represents a single security finding produced by the rule engine.
type Finding struct {
	RuleID         string
	RuleName       string
	Severity       string
	File           string
	JobID          string
	StepName       string
	LineNumber     int
	Description    string
	Evidence       string // the specific YAML snippet or expression that triggered it
	AttackScenario string
	Fix            string
	References     []string
	DemoContext     string // populated only in demo mode
}

// Engine is the rule evaluation engine that loads rule metadata and runs
// all registered rule checkers against parsed workflows.
type Engine struct {
	rules    map[string]*RuleMetadata
	checkers map[string]RuleChecker
}

// RuleChecker is a function that evaluates a single parsed workflow and returns
// any findings. Each rule ID maps to one RuleChecker.
type RuleChecker func(wf *parser.Workflow) []Finding

// NewEngine creates a new Engine, loads rule metadata from the provided filesystem,
// and registers all built-in rule checker functions.
func NewEngine(fsys fs.FS) (*Engine, error) {
	meta, err := LoadRules(fsys)
	if err != nil {
		return nil, err
	}

	e := &Engine{
		rules:    meta,
		checkers: make(map[string]RuleChecker),
	}

	e.registerCheckers()
	return e, nil
}

// NewEngineWithDefaults creates an Engine with default (empty) metadata for all rules.
// This is useful when rule YAML files are not available (e.g., in tests).
func NewEngineWithDefaults() *Engine {
	e := &Engine{
		rules:    defaultRuleMetadata(),
		checkers: make(map[string]RuleChecker),
	}
	e.registerCheckers()
	return e
}

func (e *Engine) registerCheckers() {
	e.checkers["RGS-001"] = e.checkRGS001
	e.checkers["RGS-002"] = e.checkRGS002
	e.checkers["RGS-003"] = e.checkRGS003
	e.checkers["RGS-004"] = e.checkRGS004
	e.checkers["RGS-005"] = e.checkRGS005
	e.checkers["RGS-006"] = e.checkRGS006
	e.checkers["RGS-007"] = e.checkRGS007
	e.checkers["RGS-008"] = e.checkRGS008
	e.checkers["RGS-009"] = e.checkRGS009
	e.checkers["RGS-010"] = e.checkRGS010
	e.checkers["RGS-011"] = e.checkRGS011
	e.checkers["RGS-012"] = e.checkRGS012
	e.checkers["RGS-014"] = e.checkRGS014
	e.checkers["RGS-015"] = e.checkRGS015
}

// Evaluate runs all registered checkers against all provided workflows,
// deduplicates findings, and sorts by severity then file then line number.
func (e *Engine) Evaluate(workflows []*parser.Workflow) []Finding {
	var all []Finding
	for _, wf := range workflows {
		for _, checker := range e.checkers {
			findings := checker(wf)
			all = append(all, findings...)
		}
	}
	return deduplicateAndSort(all)
}

// EvaluateWithDemoContext is the same as Evaluate but populates DemoContext
// on findings using the provided mapping from rule ID to demo context string.
func (e *Engine) EvaluateWithDemoContext(workflows []*parser.Workflow, demoContexts map[string]string) []Finding {
	var all []Finding
	for _, wf := range workflows {
		for _, checker := range e.checkers {
			findings := checker(wf)
			for i := range findings {
				if ctx, ok := demoContexts[findings[i].RuleID]; ok {
					findings[i].DemoContext = ctx
				}
			}
			all = append(all, findings...)
		}
	}
	return deduplicateAndSort(all)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// hasTrigger returns true if the workflow has the specified trigger.
func hasTrigger(wf *parser.Workflow, triggerName string) bool {
	for _, t := range wf.Triggers {
		if strings.EqualFold(t, triggerName) {
			return true
		}
	}
	return false
}

// hasCommentTrigger returns true if the workflow triggers on issue_comment,
// pull_request_review_comment, or similar comment-based events.
func hasCommentTrigger(wf *parser.Workflow) bool {
	commentTriggers := []string{
		"issue_comment",
		"pull_request_review_comment",
	}
	for _, ct := range commentTriggers {
		if hasTrigger(wf, ct) {
			return true
		}
	}
	return false
}

// checkoutsForkCode returns true if any step in the workflow checks out PR head
// (fork) code using actions/checkout with a ref pointing to the PR head.
// It also returns the matching step.
func checkoutsForkCode(wf *parser.Workflow) (bool, *parser.Step) {
	prHeadRefs := []string{
		"github.event.pull_request.head.sha",
		"github.event.pull_request.head.ref",
		"github.head_ref",
	}

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if !isCheckoutAction(step.Uses) {
				continue
			}

			// Check the ref field in the with map
			refVal, hasRef := step.With["ref"]
			if hasRef {
				lower := strings.ToLower(refVal)
				for _, prRef := range prHeadRefs {
					if strings.Contains(lower, strings.ToLower(prRef)) {
						return true, step
					}
				}
			}

			// If pull_request_target and checkout has no explicit ref, the default
			// is the base branch (safe). But if the ref contains any expression
			// referencing PR head, flag it.
			for _, expr := range step.Expressions {
				lower := strings.ToLower(expr)
				for _, prRef := range prHeadRefs {
					if strings.Contains(lower, strings.ToLower(prRef)) {
						return true, step
					}
				}
			}
		}
	}
	return false, nil
}

// hasSecretsAccess checks if a step or its parent job references secrets.
func hasSecretsAccess(step *parser.Step, job *parser.Job) bool {
	// Check step expressions
	for _, expr := range step.Expressions {
		if strings.Contains(strings.ToLower(expr), "secrets.") {
			return true
		}
	}

	// Check step env
	for _, v := range step.Env {
		if strings.Contains(strings.ToLower(v), "secrets.") {
			return true
		}
	}

	// Check job env
	for _, v := range job.Env {
		if strings.Contains(strings.ToLower(v), "secrets.") {
			return true
		}
	}

	// Check job secrets refs
	if len(job.Secrets) > 0 {
		return true
	}

	return false
}

// hasAuthorCheck returns true if any step in the job has an if condition
// that checks author_association or actor.
func hasAuthorCheck(job *parser.Job) bool {
	for _, step := range job.Steps {
		if step.If == "" {
			continue
		}
		lower := strings.ToLower(step.If)
		if strings.Contains(lower, "author_association") ||
			strings.Contains(lower, "actor") {
			return true
		}
	}
	return false
}

// severityOrder returns a numeric sort value for severity levels.
// Lower number = higher severity.
func severityOrder(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// deduplicateAndSort removes duplicate findings (same RuleID + File + JobID + LineNumber)
// and sorts by severity (critical > high > medium > low), then file, then line number.
func deduplicateAndSort(findings []Finding) []Finding {
	type dedupKey struct {
		RuleID     string
		File       string
		JobID      string
		LineNumber int
	}

	seen := make(map[dedupKey]bool)
	var unique []Finding

	for _, f := range findings {
		key := dedupKey{
			RuleID:     f.RuleID,
			File:       f.File,
			JobID:      f.JobID,
			LineNumber: f.LineNumber,
		}
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	sort.Slice(unique, func(i, j int) bool {
		si, sj := severityOrder(unique[i].Severity), severityOrder(unique[j].Severity)
		if si != sj {
			return si < sj
		}
		if unique[i].File != unique[j].File {
			return unique[i].File < unique[j].File
		}
		return unique[i].LineNumber < unique[j].LineNumber
	})

	return unique
}

// isCheckoutAction returns true if the uses string refers to actions/checkout.
func isCheckoutAction(uses string) bool {
	return strings.HasPrefix(strings.ToLower(uses), "actions/checkout")
}

// makeFinding builds a Finding from the engine's loaded rule metadata.
func (e *Engine) makeFinding(ruleID string, wf *parser.Workflow, jobID string, step *parser.Step, evidence string) Finding {
	f := Finding{
		RuleID:   ruleID,
		File:     wf.Path,
		JobID:    jobID,
		Evidence: evidence,
	}

	if step != nil {
		f.StepName = step.Name
		f.LineNumber = step.LineNumber
	}

	if meta, ok := e.rules[ruleID]; ok {
		f.RuleName = meta.Name
		f.Severity = meta.Severity
		f.Description = meta.Description
		f.AttackScenario = meta.AttackScenario
		f.Fix = meta.Fix
		f.References = meta.References
	}

	return f
}

// defaultRuleMetadata returns built-in metadata for all rules so the engine
// works even without YAML rule files.
func defaultRuleMetadata() map[string]*RuleMetadata {
	return map[string]*RuleMetadata{
		"RGS-001": {ID: "RGS-001", Name: "pull_request_target with Fork Code Checkout", Severity: "critical"},
		"RGS-002": {ID: "RGS-002", Name: "Expression Injection via Untrusted Input", Severity: "high"},
		"RGS-003": {ID: "RGS-003", Name: "Dynamic Command Construction from Step Outputs", Severity: "high"},
		"RGS-004": {ID: "RGS-004", Name: "Privileged Trigger with Secrets and No Author Check", Severity: "high"},
		"RGS-005": {ID: "RGS-005", Name: "Excessive Permissions on Untrusted Trigger", Severity: "medium"},
		"RGS-006": {ID: "RGS-006", Name: "Dangerous Sink in Run Block", Severity: "high"},
		"RGS-007": {ID: "RGS-007", Name: "Unpinned Third-Party Action", Severity: "medium"},
		"RGS-008": {ID: "RGS-008", Name: "Secrets Exposure in Run Block", Severity: "medium"},
		"RGS-009": {ID: "RGS-009", Name: "Fork Code Execution via Build Tools", Severity: "critical"},
		"RGS-010": {ID: "RGS-010", Name: "AI Agent Config Poisoning via Fork PR", Severity: "high"},
		"RGS-011": {ID: "RGS-011", Name: "MCP Config Injection via Fork Checkout", Severity: "high"},
		"RGS-012": {ID: "RGS-012", Name: "External Network Access with Secrets Context", Severity: "medium"},
		"RGS-014": {ID: "RGS-014", Name: "Expression Injection via workflow_dispatch Input", Severity: "high"},
		"RGS-015": {ID: "RGS-015", Name: "Actions Runner Debug Logging Enabled", Severity: "medium"},
	}
}

// ---------------------------------------------------------------------------
// Compiled regex patterns shared across checkers
// ---------------------------------------------------------------------------

var (
	// stepOutputPattern matches ${{ steps.<id>.outputs.<name> }} style expressions.
	stepOutputPattern = regexp.MustCompile(`\$\{\{\s*steps\.\w+\.outputs\.\w+`)

	// gitDiffPattern matches git diff, find, ls commands in run blocks.
	gitDiffPattern = regexp.MustCompile(`(?i)(git\s+diff|git\s+log|find\s+|ls\s+|git\s+show)`)

	// shaPattern matches a 40-character hexadecimal SHA.
	shaPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

	// executionCommandPattern matches build tool / interpreter invocations.
	executionCommandPattern = regexp.MustCompile(`(?i)\b(go\s+run|go\s+build|go\s+test|make\b|node\s|npm\s|npx\s|python\s|python3\s|pip\s|pip3\s|ruby\s|bash\s|sh\s)`)

	// aiConfigPattern matches AI agent configuration file references.
	aiConfigPattern = regexp.MustCompile(`(?i)(CLAUDE\.md|\.claude/|copilot-instructions\.md|AGENTS\.md|\.github/copilot-instructions)`)

	// mcpConfigPattern matches MCP configuration file references.
	mcpConfigPattern = regexp.MustCompile(`(?i)(\.mcp\.json|mcp-config\.json|mcp_servers\.json|\.cursor/mcp\.json|claude_desktop_config\.json)`)

	// curlWgetPattern matches curl or wget commands.
	curlWgetPattern = regexp.MustCompile(`(?i)\b(curl|wget)\s+`)

	// urlPattern extracts URLs from curl/wget invocations.
	urlPattern = regexp.MustCompile(`https?://[^\s"'` + "`" + `]+`)

	// dispatchInputPattern matches ${{ github.event.inputs.* }} expressions.
	dispatchInputPattern = regexp.MustCompile(`(?i)github\.event\.inputs\.`)

	// exprPattern matches ${{ ... }} expression syntax in run blocks.
	exprPattern = regexp.MustCompile(`\$\{\{[^}]+\}\}`)

	// sensitivePermissions lists scopes where write access is dangerous.
	sensitivePermissions = []string{
		"contents",
		"packages",
		"deployments",
		"id-token",
		"actions",
		"security-events",
		"pages",
		"pull-requests",
		"issues",
		"statuses",
		"checks",
	}
)

// ---------------------------------------------------------------------------
// RGS-001: pull_request_target with Fork Code Checkout
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS001(wf *parser.Workflow) []Finding {
	if !hasTrigger(wf, "pull_request_target") {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if !isCheckoutAction(step.Uses) {
				continue
			}

			prHeadRefs := []string{
				"github.event.pull_request.head.sha",
				"github.event.pull_request.head.ref",
				"github.head_ref",
			}

			// Check with.ref for PR head references
			refVal, hasRef := step.With["ref"]
			if hasRef {
				lower := strings.ToLower(refVal)
				for _, prRef := range prHeadRefs {
					if strings.Contains(lower, strings.ToLower(prRef)) {
						f := e.makeFinding("RGS-001", wf, jobID, step,
							"actions/checkout with ref: "+refVal)
						findings = append(findings, f)
						break
					}
				}
			}

			// Also check all expressions in the step for PR head refs
			if !hasRef {
				for _, expr := range step.Expressions {
					lower := strings.ToLower(expr)
					for _, prRef := range prHeadRefs {
						if strings.Contains(lower, strings.ToLower(prRef)) {
							f := e.makeFinding("RGS-001", wf, jobID, step,
								"actions/checkout expression references PR head: "+expr)
							findings = append(findings, f)
							break
						}
					}
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-002: Expression Injection via Untrusted Input
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS002(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Only check expressions in the run block itself, not in env/with
			// (where they are safely assigned to variables).
			for _, expr := range exprPattern.FindAllString(step.Run, -1) {
				if taint.IsTainted(expr, taint.Tier1Sources) {
					f := e.makeFinding("RGS-002", wf, jobID, step,
						"Tainted expression in run block: "+expr)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-003: Dynamic Command Construction from Step Outputs
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS003(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check for git diff/find/ls patterns in the run block
			if !gitDiffPattern.MatchString(step.Run) {
				continue
			}

			// Check for step output expressions
			if stepOutputPattern.MatchString(step.Run) {
				f := e.makeFinding("RGS-003", wf, jobID, step,
					"Run block uses git diff/find/ls and references step outputs: "+
						truncate(step.Run, 200))
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-004: Privileged Trigger with Secrets and No Author Check
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS004(wf *parser.Workflow) []Finding {
	privilegedTriggers := hasCommentTrigger(wf) ||
		hasTrigger(wf, "workflow_run") ||
		hasTrigger(wf, "issue_comment")

	if !privilegedTriggers {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		if hasAuthorCheck(job) {
			continue
		}

		for _, step := range job.Steps {
			if hasSecretsAccess(step, job) {
				f := e.makeFinding("RGS-004", wf, jobID, step,
					"Privileged trigger with secrets access and no author/actor check")
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-005: Excessive Permissions on Untrusted Trigger
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS005(wf *parser.Workflow) []Finding {
	untrusted := hasTrigger(wf, "pull_request_target") || hasCommentTrigger(wf)
	if !untrusted {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, scope := range sensitivePermissions {
			perm, ok := job.Permissions[scope]
			if ok && strings.EqualFold(perm, "write") {
				f := e.makeFinding("RGS-005", wf, jobID, nil,
					"Permission '"+scope+": write' on untrusted trigger")
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-006: Dangerous Sink in Run Block
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS006(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			found, desc := taint.HasDangerousSink(step.Run)
			if found {
				// Only flag if there are also expressions in the run block
				if len(step.Expressions) > 0 {
					evidence := "Dangerous sink (" + desc + ") with expression injection: " + truncate(step.Run, 200)
					f := e.makeFinding("RGS-006", wf, jobID, step, evidence)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-007: Unpinned Third-Party Action
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS007(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}

			// Skip first-party and local actions
			lower := strings.ToLower(step.Uses)
			if strings.HasPrefix(lower, "actions/") ||
				strings.HasPrefix(lower, "github/") ||
				strings.HasPrefix(lower, "./") {
				continue
			}

			// Parse the ref from uses (format: owner/repo@ref)
			atIdx := strings.LastIndex(step.Uses, "@")
			if atIdx == -1 {
				// No ref at all — flag it
				f := e.makeFinding("RGS-007", wf, jobID, step,
					"Third-party action with no version pin: "+step.Uses)
				findings = append(findings, f)
				continue
			}

			ref := step.Uses[atIdx+1:]
			if !shaPattern.MatchString(ref) {
				f := e.makeFinding("RGS-007", wf, jobID, step,
					"Third-party action pinned to mutable ref '"+ref+"': "+step.Uses)
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-008: Secrets Exposure in Run Block
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS008(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Only check expressions in the run block itself, not in env/with
			// (where they are safely assigned to variables — the correct pattern).
			for _, expr := range exprPattern.FindAllString(step.Run, -1) {
				lower := strings.ToLower(expr)
				if strings.Contains(lower, "secrets.") || strings.Contains(lower, "github.token") {
					f := e.makeFinding("RGS-008", wf, jobID, step,
						"Secrets/token referenced in run block: "+expr)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-009: Fork Code Execution via Build Tools
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS009(wf *parser.Workflow) []Finding {
	if !hasTrigger(wf, "pull_request_target") {
		return nil
	}

	forkCheckout, checkoutStep := checkoutsForkCode(wf)
	if !forkCheckout {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			if executionCommandPattern.MatchString(step.Run) {
				evidence := "Fork code checkout"
				if checkoutStep != nil {
					evidence += " at step '" + checkoutStep.Name + "'"
				}
				evidence += " followed by build/exec command: " + truncate(step.Run, 200)

				f := e.makeFinding("RGS-009", wf, jobID, step, evidence)
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-010: AI Agent Config Poisoning via Fork PR
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS010(wf *parser.Workflow) []Finding {
	if !hasTrigger(wf, "pull_request_target") {
		return nil
	}

	forkCheckout, _ := checkoutsForkCode(wf)
	if !forkCheckout {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			// Check run blocks for AI config file references
			if step.Run != "" && aiConfigPattern.MatchString(step.Run) {
				f := e.makeFinding("RGS-010", wf, jobID, step,
					"Fork checkout with AI config file reference in run block: "+truncate(step.Run, 200))
				findings = append(findings, f)
			}

			// Check step names for AI config references
			if step.Name != "" && aiConfigPattern.MatchString(step.Name) {
				f := e.makeFinding("RGS-010", wf, jobID, step,
					"Fork checkout with AI config reference in step name: "+step.Name)
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-011: MCP Config Injection via Fork Checkout
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS011(wf *parser.Workflow) []Finding {
	forkCheckout, _ := checkoutsForkCode(wf)
	if !forkCheckout {
		return nil
	}

	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			// Check run blocks for MCP config file references
			if step.Run != "" && mcpConfigPattern.MatchString(step.Run) {
				f := e.makeFinding("RGS-011", wf, jobID, step,
					"Fork checkout with MCP config file reference: "+truncate(step.Run, 200))
				findings = append(findings, f)
			}

			// Check checkout path for MCP config
			if isCheckoutAction(step.Uses) {
				if path, ok := step.With["path"]; ok && mcpConfigPattern.MatchString(path) {
					f := e.makeFinding("RGS-011", wf, jobID, step,
						"Fork checkout into path containing MCP config: "+path)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-012: External Network Access with Secrets Context
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS012(wf *parser.Workflow) []Finding {
	var findings []Finding

	githubDomains := []string{
		"github.com",
		"api.github.com",
		"raw.githubusercontent.com",
		"github.io",
		"ghcr.io",
		"pkg.github.com",
	}

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check if step has curl/wget
			if !curlWgetPattern.MatchString(step.Run) {
				continue
			}

			// Check if the step or job has secrets or publishing access
			if !hasSecretsAccess(step, job) {
				continue
			}

			// Extract URLs and check if any are non-GitHub
			urls := urlPattern.FindAllString(step.Run, -1)
			for _, u := range urls {
				isGitHub := false
				for _, ghDomain := range githubDomains {
					if strings.Contains(strings.ToLower(u), ghDomain) {
						isGitHub = true
						break
					}
				}
				if !isGitHub {
					f := e.makeFinding("RGS-012", wf, jobID, step,
						"curl/wget to non-GitHub URL with secrets access: "+u)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-014: Expression Injection via workflow_dispatch Input
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS014(wf *parser.Workflow) []Finding {
	var findings []Finding

	for jobID, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Only flag expressions that appear in the run block itself,
			// not in env/with (where they are safely assigned to variables).
			for _, expr := range exprPattern.FindAllString(step.Run, -1) {
				if dispatchInputPattern.MatchString(expr) {
					f := e.makeFinding("RGS-014", wf, jobID, step,
						"workflow_dispatch input interpolated in run block: "+expr)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// RGS-015: Actions Runner Debug Logging Enabled
// ---------------------------------------------------------------------------

func (e *Engine) checkRGS015(wf *parser.Workflow) []Finding {
	var findings []Finding

	debugVars := []string{"ACTIONS_RUNNER_DEBUG", "ACTIONS_STEP_DEBUG"}

	// Check workflow-level env.
	if envRaw, ok := wf.Raw["env"]; ok {
		if envMap, ok := envRaw.(map[string]interface{}); ok {
			for _, dv := range debugVars {
				if val, ok := envMap[dv]; ok {
					if isTrue(val) {
						f := e.makeFinding("RGS-015", wf, "", nil,
							"Debug variable "+dv+" enabled at workflow level")
						findings = append(findings, f)
					}
				}
			}
		}
	}

	// Check job-level and step-level env.
	for jobID, job := range wf.Jobs {
		for _, dv := range debugVars {
			if val, ok := job.Env[dv]; ok {
				if strings.EqualFold(val, "true") {
					f := e.makeFinding("RGS-015", wf, jobID, nil,
						"Debug variable "+dv+" enabled at job level")
					findings = append(findings, f)
				}
			}
		}

		for _, step := range job.Steps {
			for _, dv := range debugVars {
				if val, ok := step.Env[dv]; ok {
					if strings.EqualFold(val, "true") {
						f := e.makeFinding("RGS-015", wf, jobID, step,
							"Debug variable "+dv+" enabled at step level")
						findings = append(findings, f)
					}
				}
			}
		}
	}

	return findings
}

// isTrue checks if a YAML value represents boolean true.
func isTrue(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return strings.EqualFold(val, "true")
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

// truncate shortens a string to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	// Normalize newlines and collapse whitespace for display
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
