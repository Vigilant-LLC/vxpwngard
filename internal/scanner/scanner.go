// Package scanner orchestrates the parse -> rule evaluation -> reporting
// pipeline for Runner Guard. It ties together the parser, rule engine, and
// reporter packages behind a single Run / RunOnBytes entry point.
package scanner

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/Vigilant-LLC/runner-guard/internal/config"
	"github.com/Vigilant-LLC/runner-guard/internal/parser"
	"github.com/Vigilant-LLC/runner-guard/internal/rules"
)

// Config holds every tuneable knob for a single scan invocation.
type Config struct {
	Path         string            // directory to scan (for Run)
	Format       string            // console, json, sarif
	FailOn       string            // low, medium, high, critical
	Baseline     string            // path to baseline JSON file
	ChangedOnly  bool              // only scan workflow files changed in git
	ChangedFiles []string          // pre-computed list of changed files (if set, overrides ChangedOnly)
	NoColor      bool              // suppress ANSI colour codes
	Output       string            // output file path (empty = stdout)
	IsDemo       bool              // true when invoked via the demo command
	DemoContexts map[string]string // rule ID -> demo context string
	RulesFS      fs.FS             // embedded rules filesystem
	IgnoreRules  []string          // rule IDs to suppress
	IgnoreFiles  []string          // file glob patterns to suppress
}

// Result carries the outcomes of a scan: the list of findings and the
// exit code the CLI should return.
type Result struct {
	Findings []rules.Finding
	ExitCode int
}

// severityLevel converts a severity name to a numeric value for comparison.
// critical=4, high=3, medium=2, low=1.
func severityLevel(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// fingerprint computes a stable MD5-based identifier for a finding so that
// baseline suppression can match findings across runs.
func fingerprint(f rules.Finding) string {
	h := md5.New()
	_, _ = fmt.Fprintf(h, "%s%s%s%s", f.RuleID, f.File, strconv.Itoa(f.LineNumber), f.Evidence)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// loadBaseline reads a JSON file containing an array of fingerprint strings.
func loadBaseline(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline %s: %w", path, err)
	}

	var fingerprints []string
	if err := json.Unmarshal(data, &fingerprints); err != nil {
		return nil, fmt.Errorf("parsing baseline %s: %w", path, err)
	}

	set := make(map[string]bool, len(fingerprints))
	for _, fp := range fingerprints {
		set[fp] = true
	}
	return set, nil
}

// suppressBaseline removes findings whose fingerprints appear in the baseline
// set and returns the remaining findings.
func suppressBaseline(findings []rules.Finding, baseline map[string]bool) []rules.Finding {
	var kept []rules.Finding
	for _, f := range findings {
		if !baseline[fingerprint(f)] {
			kept = append(kept, f)
		}
	}
	return kept
}

// determineExitCode returns 1 if any finding has a severity at or above the
// configured fail-on threshold, or 0 otherwise.
func determineExitCode(findings []rules.Finding, failOn string) int {
	threshold := severityLevel(failOn)
	if threshold == 0 {
		// If the caller provided an unrecognised value, default to "high".
		threshold = severityLevel("high")
	}

	for _, f := range findings {
		if severityLevel(f.Severity) >= threshold {
			return 1
		}
	}
	return 0
}

// Run performs a full scan of the directory tree at cfg.Path.
//
//  1. Parses all workflow files under cfg.Path/.github/workflows/.
//  2. Optionally filters to only changed files (--changed-only).
//  3. Creates a rule engine loaded with metadata from cfg.RulesFS.
//  4. Evaluates all parsed workflows against the rule set.
//  5. Applies config-based, inline, and baseline suppressions.
//  6. Determines the exit code based on cfg.FailOn.
func Run(cfg Config) (*Result, error) {
	// 1. Parse workflows from the target directory.
	var workflows []*parser.Workflow
	var err error

	if len(cfg.ChangedFiles) > 0 {
		// Parse only the specified files.
		for _, f := range cfg.ChangedFiles {
			wf, parseErr := parser.ParseFile(f)
			if parseErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", f, parseErr)
				continue
			}
			workflows = append(workflows, wf)
		}
	} else {
		workflows, err = parser.ParseDirectory(cfg.Path)
		if err != nil {
			return nil, fmt.Errorf("scanning %s: %w", cfg.Path, err)
		}
	}

	// 2. Filter by ignored files.
	if len(cfg.IgnoreFiles) > 0 {
		cfgObj := &config.Config{IgnoreFiles: cfg.IgnoreFiles}
		var kept []*parser.Workflow
		for _, wf := range workflows {
			if !cfgObj.ShouldIgnoreFile(wf.Path) {
				kept = append(kept, wf)
			}
		}
		workflows = kept
	}

	// 3. Build the rule engine.
	engine, err := newEngine(cfg)
	if err != nil {
		return nil, err
	}

	// 4. Evaluate.
	findings := evaluate(engine, workflows, cfg)

	// 5. Apply suppressions: config rules, inline directives, baseline.
	findings = applyConfigSuppressions(findings, cfg)
	findings = applyInlineSuppressions(findings, workflows, cfg)
	findings, err = applyBaseline(findings, cfg.Baseline)
	if err != nil {
		return nil, err
	}

	// 6. Exit code.
	exitCode := 0
	if !cfg.IsDemo {
		exitCode = determineExitCode(findings, cfg.FailOn)
	}

	return &Result{
		Findings: findings,
		ExitCode: exitCode,
	}, nil
}

// RunOnBytes performs a scan on in-memory workflow file contents instead of
// reading from disk.  This is the entry point used by the demo command, which
// loads workflow content from the embedded filesystem.
//
// The files map is keyed by filename (used as the Workflow.Path) with the
// value being the raw YAML bytes.
func RunOnBytes(cfg Config, files map[string][]byte) (*Result, error) {
	// 1. Parse each provided file.
	var workflows []*parser.Workflow
	for name, data := range files {
		wf, err := parser.ParseBytes(data, name)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		workflows = append(workflows, wf)
	}

	// 2. Build the rule engine.
	engine, err := newEngine(cfg)
	if err != nil {
		return nil, err
	}

	// 3. Evaluate.
	findings := evaluate(engine, workflows, cfg)

	// 4. Baseline suppression (typically not used in demo mode, but supported).
	findings, err = applyBaseline(findings, cfg.Baseline)
	if err != nil {
		return nil, err
	}

	// 5. Exit code — demo mode never returns non-zero.
	exitCode := 0
	if !cfg.IsDemo {
		exitCode = determineExitCode(findings, cfg.FailOn)
	}

	return &Result{
		Findings: findings,
		ExitCode: exitCode,
	}, nil
}

// GenerateBaselineFingerprints scans the given path and returns the
// fingerprints of all current findings. This is used by the baseline command
// to write the initial suppression file.
func GenerateBaselineFingerprints(cfg Config) ([]string, int, error) {
	result, err := Run(cfg)
	if err != nil {
		return nil, 0, err
	}

	fingerprints := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		fingerprints = append(fingerprints, fingerprint(f))
	}
	return fingerprints, len(result.Findings), nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// newEngine creates a rules.Engine, falling back to defaults if no RulesFS
// was provided or if loading fails gracefully.
func newEngine(cfg Config) (*rules.Engine, error) {
	if cfg.RulesFS != nil {
		engine, err := rules.NewEngine(cfg.RulesFS)
		if err != nil {
			return nil, fmt.Errorf("loading rules: %w", err)
		}
		return engine, nil
	}
	// Fall back to built-in defaults when no embedded FS is available.
	return rules.NewEngineWithDefaults(), nil
}

// evaluate runs the engine against workflows, optionally injecting demo
// context strings into findings.
func evaluate(engine *rules.Engine, workflows []*parser.Workflow, cfg Config) []rules.Finding {
	if cfg.IsDemo && len(cfg.DemoContexts) > 0 {
		return engine.EvaluateWithDemoContext(workflows, cfg.DemoContexts)
	}
	return engine.Evaluate(workflows)
}

// applyBaseline loads a baseline file (if configured) and removes matching
// findings. Returns the original slice unchanged when no baseline is set.
func applyBaseline(findings []rules.Finding, baselinePath string) ([]rules.Finding, error) {
	if baselinePath == "" {
		return findings, nil
	}

	baseline, err := loadBaseline(baselinePath)
	if err != nil {
		return nil, err
	}

	return suppressBaseline(findings, baseline), nil
}

// applyConfigSuppressions removes findings for rules listed in cfg.IgnoreRules.
func applyConfigSuppressions(findings []rules.Finding, cfg Config) []rules.Finding {
	if len(cfg.IgnoreRules) == 0 {
		return findings
	}

	cfgObj := &config.Config{IgnoreRules: cfg.IgnoreRules}
	var kept []rules.Finding
	for _, f := range findings {
		if !cfgObj.ShouldIgnoreRule(f.RuleID) {
			kept = append(kept, f)
		}
	}
	return kept
}

// applyInlineSuppressions removes findings that have # runner-guard:ignore
// directives in their source workflow files.
func applyInlineSuppressions(findings []rules.Finding, workflows []*parser.Workflow, cfg Config) []rules.Finding {
	// Build a map of file content for inline suppression extraction.
	// We read the raw bytes of each workflow file to find inline directives.
	suppressionsByFile := make(map[string][]config.InlineSuppression)
	for _, wf := range workflows {
		data, err := os.ReadFile(wf.Path)
		if err != nil {
			continue // if file can't be re-read, skip inline suppression for it
		}
		sups := config.ExtractInlineSuppressions(data, wf.Path)
		if len(sups) > 0 {
			suppressionsByFile[wf.Path] = sups
		}
	}

	if len(suppressionsByFile) == 0 {
		return findings
	}

	var kept []rules.Finding
	for _, f := range findings {
		sups, ok := suppressionsByFile[f.File]
		if ok && config.IsInlineSuppressed(sups, f.RuleID, f.File, f.LineNumber) {
			continue // suppressed
		}
		kept = append(kept, f)
	}
	return kept
}
