// Runner Guard — CI/CD Pipeline Security Scanner
// Copyright (c) Vigilant. All rights reserved.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	runnerguard "github.com/Vigilant-LLC/runner-guard"
	"github.com/Vigilant-LLC/runner-guard/internal/autofix"
	"github.com/Vigilant-LLC/runner-guard/internal/config"
	"github.com/Vigilant-LLC/runner-guard/internal/git"
	ghclient "github.com/Vigilant-LLC/runner-guard/internal/github"
	"github.com/Vigilant-LLC/runner-guard/internal/reporter"
	"github.com/Vigilant-LLC/runner-guard/internal/rules"
	"github.com/Vigilant-LLC/runner-guard/internal/scanner"
)

// Build-time variables injected via ldflags:
//
//	go build -ldflags "-X main.version=1.0.0 -X main.commit=$(git rev-parse HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var (
	version = "0.1.0"
	commit  = "dev"
	date    = "unknown"
)

// separator is the heavy horizontal line used in headers and demo banners.
var separator = strings.Repeat("\u2501", 58)

// ---------------------------------------------------------------------------
// Demo scenario definitions
// ---------------------------------------------------------------------------

type demoScenario struct {
	Key         string // CLI name: fork-checkout, microsoft, ai-injection
	File        string // filename inside demo/vulnerable/workflows/
	Title       string // banner title
	Description string // banner body
	Context     string // DemoContext string injected into findings
}

var scenarios = []demoScenario{
	{
		Key:  "fork-checkout",
		File: "ci-vulnerable.yml",
		Title: "Fork Checkout Kill Chain",
		Description: "This workflow replicates the configuration pattern exploited\n" +
			"by autonomous AI agents to steal PATs, tamper with releases,\n" +
			"and push malicious code via privileged fork checkouts.",
		Context: "This is the exact pattern used in documented CI/CD pipeline compromises.",
	},
	{
		Key:  "microsoft",
		File: "comment-trigger.yml",
		Title: "Microsoft / Akri Issue-Comment Injection",
		Description: "This workflow replicates the issue_comment injection\n" +
			"pattern found across hundreds of Microsoft repositories,\n" +
			"enabling arbitrary code execution via crafted comments.",
		Context: "This replicates the Microsoft/Akri issue_comment injection pattern.",
	},
	{
		Key:  "ai-injection",
		File: "ai-config-attack.yml",
		Title: "AI Config Poisoning via Fork PR",
		Description: "This demonstrates how AI config files (CLAUDE.md) can be\n" +
			"weaponized through fork PRs when checked out and processed\n" +
			"in a privileged pull_request_target context.",
		Context: "This demonstrates how AI config files (CLAUDE.md) can be weaponized through fork PRs.",
	},
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	rootCmd := newRootCmd()

	rootCmd.AddCommand(
		newScanCmd(),
		newDemoCmd(),
		newBaselineCmd(),
		newFixCmd(),
		newVersionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Root command
// ---------------------------------------------------------------------------

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "runner-guard",
		Short: "Runner Guard — CI/CD Pipeline Security Scanner",
		Long: `Runner Guard detects source-to-sink injection vulnerabilities, excessive
permissions, unpinned actions, AI config poisoning, and other security
anti-patterns in GitHub Actions workflows.

Built by Vigilant.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

// ---------------------------------------------------------------------------
// scan command
// ---------------------------------------------------------------------------

func newScanCmd() *cobra.Command {
	var (
		format      string
		failOn      string
		baseline    string
		changedOnly bool
		output      string
		noColor     bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan GitHub Actions workflows for security issues",
		Long: `Scan recursively finds .yml/.yaml files under <path>/.github/workflows/
and evaluates them against Runner Guard's built-in rule set.

Path can be:
  - A local directory:     runner-guard scan .
  - A GitHub repository:   runner-guard scan github.com/owner/repo
  - With a branch:         runner-guard scan github.com/owner/repo@main`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()
			path := args[0]

			// Honour --no-color and auto-detect non-TTY.
			if noColor || !isTTY() {
				color.NoColor = true
			}

			printHeader(os.Stderr)

			// Load .runner-guard.yaml config file.
			fileCfg := loadConfigFile(path)

			// Merge config file settings with CLI flags (CLI flags take precedence).
			effectiveFailOn := mergeString(failOn, "high", fileCfg)
			effectiveFormat := mergeString(format, "console", fileCfg)
			effectiveBaseline := baseline
			if effectiveBaseline == "" && fileCfg != nil && fileCfg.Baseline != "" {
				effectiveBaseline = fileCfg.Baseline
			}
			effectiveChangedOnly := changedOnly
			if !effectiveChangedOnly && fileCfg != nil && fileCfg.ChangedOnly {
				effectiveChangedOnly = true
			}

			cfg := scanner.Config{
				Path:        path,
				Format:      effectiveFormat,
				FailOn:      effectiveFailOn,
				Baseline:    effectiveBaseline,
				ChangedOnly: effectiveChangedOnly,
				NoColor:     noColor || !isTTY(),
				Output:      output,
				RulesFS:     runnerguard.RulesFS,
			}

			// Apply config-based ignore rules/files.
			if fileCfg != nil {
				cfg.IgnoreRules = fileCfg.IgnoreRules
				cfg.IgnoreFiles = fileCfg.IgnoreFiles
			}

			var result *scanner.Result
			var err error

			if ghclient.IsRemotePath(path) {
				// Remote GitHub scanning.
				result, err = runRemoteScan(cfg)
			} else if cfg.ChangedOnly {
				// Changed-only mode: resolve changed files first.
				result, err = runChangedOnlyScan(cfg)
			} else {
				result, err = scanner.Run(cfg)
			}

			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Select output destination.
			var w io.Writer = os.Stdout
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				w = f
			}

			duration := time.Since(start)

			// Write report in the chosen format.
			if err := writeReport(w, result.Findings, effectiveFormat, noColor || !isTTY(), duration, false); err != nil {
				return err
			}

			os.Exit(result.ExitCode)
			return nil // unreachable, but keeps the compiler happy
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "console", "Output format: console, json, sarif")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Minimum severity to exit non-zero: low, medium, high, critical")
	cmd.Flags().StringVar(&baseline, "baseline", "", "Path to baseline JSON file for suppression")
	cmd.Flags().BoolVar(&changedOnly, "changed-only", false, "Only scan workflow files changed in current git branch")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write report to file instead of stdout")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable ANSI color output")

	return cmd
}

// ---------------------------------------------------------------------------
// demo command
// ---------------------------------------------------------------------------

func newDemoCmd() *cobra.Command {
	var scenario string

	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Run built-in demo scenarios showing real-world CI/CD attack patterns",
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()

			// Demo always uses console, always uses color (unless non-TTY).
			noColor := !isTTY()
			if noColor {
				color.NoColor = true
			}

			printHeader(os.Stderr)

			// Determine which scenarios to run.
			selected := filterScenarios(scenario)
			if len(selected) == 0 {
				return fmt.Errorf("unknown scenario %q; options: all, fork-checkout, microsoft, ai-injection", scenario)
			}

			for _, sc := range selected {
				// Print scenario banner.
				printDemoBanner(sc)

				// Load the demo workflow file from the embedded FS.
				files, err := loadDemoFiles(runnerguard.DemoFS, sc)
				if err != nil {
					return err
				}

				// Build demo contexts map — every rule gets this scenario's context.
				demoContexts := buildDemoContexts(sc)

				cfg := scanner.Config{
					Format:       "console",
					FailOn:       "critical", // never exit non-zero in demo
					NoColor:      noColor,
					IsDemo:       true,
					DemoContexts: demoContexts,
					RulesFS:      runnerguard.RulesFS,
				}

				result, err := scanner.RunOnBytes(cfg, files)
				if err != nil {
					return fmt.Errorf("demo scan failed for %s: %w", sc.Key, err)
				}

				duration := time.Since(start)
				reporter.ReportConsole(os.Stdout, result.Findings, noColor, duration, true)
				fmt.Fprintln(os.Stdout)
			}

			// Closing prompt.
			boldCyan := color.New(color.FgCyan, color.Bold)
			boldCyan.Fprintln(os.Stdout, "\u2192 Run runner-guard scan . to check your own pipelines")

			return nil
		},
	}

	cmd.Flags().StringVar(&scenario, "scenario", "all", "Demo scenario: all, fork-checkout, microsoft, ai-injection")

	return cmd
}

// ---------------------------------------------------------------------------
// baseline command
// ---------------------------------------------------------------------------

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline [path]",
		Short: "Generate a baseline file from current findings",
		Long: `Scans the given path and writes all current finding fingerprints to
.runner-guard-baseline.json. Future scans using --baseline will suppress
these findings, letting you focus on new issues.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			cfg := scanner.Config{
				Path:    path,
				Format:  "console",
				FailOn:  "critical",
				RulesFS: runnerguard.RulesFS,
			}

			fingerprints, count, err := scanner.GenerateBaselineFingerprints(cfg)
			if err != nil {
				return fmt.Errorf("baseline scan failed: %w", err)
			}

			data, err := json.MarshalIndent(fingerprints, "", "  ")
			if err != nil {
				return fmt.Errorf("encoding baseline: %w", err)
			}

			outputPath := ".runner-guard-baseline.json"
			if err := os.WriteFile(outputPath, data, 0644); err != nil {
				return fmt.Errorf("writing baseline file: %w", err)
			}

			fmt.Fprintf(os.Stdout, "Baseline written: %d findings recorded. Future scans will suppress these.\n", count)
			return nil
		},
	}

	return cmd
}

// ---------------------------------------------------------------------------
// version command
// ---------------------------------------------------------------------------

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Runner Guard version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stdout, "runner-guard version v%s (commit: %s, built: %s)\n", version, commit, date)
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// printHeader prints the CLI banner to the given writer.
func printHeader(w io.Writer) {
	fmt.Fprintf(w, "Runner Guard v%s | Vigilant\n", version)
	fmt.Fprintln(w, separator)
}

// printDemoBanner prints a scenario-specific demo banner to stdout.
func printDemoBanner(sc demoScenario) {
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, separator)
	boldWhite := color.New(color.FgWhite, color.Bold)
	boldWhite.Fprintf(os.Stdout, "DEMO SCENARIO: %s\n", sc.Title)
	fmt.Fprintln(os.Stdout, sc.Description)
	fmt.Fprintln(os.Stdout, separator)
	fmt.Fprintln(os.Stdout)
}

// filterScenarios returns the subset of scenarios matching the --scenario flag.
func filterScenarios(name string) []demoScenario {
	if strings.EqualFold(name, "all") || name == "" {
		return scenarios
	}

	for _, sc := range scenarios {
		if strings.EqualFold(sc.Key, name) {
			return []demoScenario{sc}
		}
	}
	return nil
}

// loadDemoFiles reads the demo workflow file from the embedded FS and returns
// it as a map suitable for scanner.RunOnBytes.
func loadDemoFiles(demoFS fs.FS, sc demoScenario) (map[string][]byte, error) {
	path := "demo/vulnerable/workflows/" + sc.File
	data, err := fs.ReadFile(demoFS, path)
	if err != nil {
		return nil, fmt.Errorf("loading demo file %s: %w", path, err)
	}
	return map[string][]byte{sc.File: data}, nil
}

// buildDemoContexts creates a demo context map where every known rule ID maps
// to the scenario's context string. This ensures that any rule that fires on
// the demo file will carry the contextual explanation.
func buildDemoContexts(sc demoScenario) map[string]string {
	// All 12 rules could potentially fire on a demo file.
	ruleIDs := []string{
		"RGS-001", "RGS-002", "RGS-003", "RGS-004",
		"RGS-005", "RGS-006", "RGS-007", "RGS-008",
		"RGS-009", "RGS-010", "RGS-011", "RGS-012",
	}

	contexts := make(map[string]string, len(ruleIDs))
	for _, id := range ruleIDs {
		contexts[id] = sc.Context
	}
	return contexts
}

// writeReport dispatches to the appropriate reporter based on the format string.
func writeReport(w io.Writer, findings []rules.Finding, format string, noColor bool, duration time.Duration, isDemo bool) error {
	switch strings.ToLower(format) {
	case "json":
		return reporter.ReportJSON(w, findings)
	case "sarif":
		return reporter.ReportSARIF(w, findings)
	default: // "console" or anything unrecognised
		reporter.ReportConsole(w, findings, noColor, duration, isDemo)
		return nil
	}
}

// ---------------------------------------------------------------------------
// fix command
// ---------------------------------------------------------------------------

func newFixCmd() *cobra.Command {
	var dryRun bool
	var ruleFilter string

	cmd := &cobra.Command{
		Use:   "fix [path]",
		Short: "Auto-fix security issues in GitHub Actions workflows",
		Long: `Scans workflow files and automatically remediates security findings.

Supported auto-fixes:
  RGS-002  Extract untrusted expressions from run blocks into env vars
  RGS-007  Pin third-party actions to commit SHAs
  RGS-008  Extract secrets from run blocks into env vars
  RGS-014  Extract workflow_dispatch inputs from run blocks into env vars
  RGS-015  Remove ACTIONS_RUNNER_DEBUG / ACTIONS_STEP_DEBUG env vars

Use --dry-run to preview changes without modifying files.
Use --rule to apply a specific rule's fix (e.g. --rule RGS-007).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}

			printHeader(os.Stderr)

			// Determine which fixes to run.
			fixFuncs := make(map[string]autofix.FixFunc)
			if ruleFilter != "" {
				fn, ok := autofix.Registry[ruleFilter]
				if !ok {
					return fmt.Errorf("no auto-fix available for rule %s", ruleFilter)
				}
				fixFuncs[ruleFilter] = fn
			} else {
				for id, fn := range autofix.Registry {
					fixFuncs[id] = fn
				}
			}

			var allResults []autofix.FixResult
			for ruleID, fn := range fixFuncs {
				results, err := fn(dir, dryRun)
				if err != nil {
					errColor := color.New(color.FgRed)
					errColor.Fprintf(os.Stderr, "  Warning: %s fix failed: %v\n", ruleID, err)
					continue
				}
				allResults = append(allResults, results...)
			}

			if len(allResults) == 0 {
				boldGreen := color.New(color.FgGreen, color.Bold)
				boldGreen.Fprintln(os.Stdout, "\u2713 No auto-fixable issues found.")
				return nil
			}

			verb := "Fixed"
			if dryRun {
				verb = "Would fix"
			}

			var succeeded, failed int
			for _, r := range allResults {
				if r.Error != "" {
					failed++
					errColor := color.New(color.FgRed)
					errColor.Fprintf(os.Stdout, "  \u2717 [%s] %s\n", r.RuleID, r.Error)
				} else {
					succeeded++
					okColor := color.New(color.FgGreen)
					okColor.Fprintf(os.Stdout, "  \u2713 [%s] %s\n", r.RuleID, r.Detail)
					fileColor := color.New(color.FgBlue)
					fileColor.Fprintf(os.Stdout, "    %s (line %d)\n", r.File, r.LineNum)
				}
			}

			fmt.Fprintln(os.Stdout)
			if dryRun {
				fmt.Fprintf(os.Stdout, "Dry run: %d fixes would be applied", succeeded)
			} else {
				fmt.Fprintf(os.Stdout, "%s: %d issues remediated", verb, succeeded)
			}
			if failed > 0 {
				fmt.Fprintf(os.Stdout, " (%d failed)", failed)
			}
			fmt.Fprintln(os.Stdout)

			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview changes without modifying files")
	cmd.Flags().StringVar(&ruleFilter, "rule", "", "Apply fix for a specific rule only (e.g. RGS-007)")

	return cmd
}

// ---------------------------------------------------------------------------
// Remote scanning helper
// ---------------------------------------------------------------------------

func runRemoteScan(cfg scanner.Config) (*scanner.Result, error) {
	fmt.Fprintf(os.Stderr, "Fetching workflows from %s...\n", cfg.Path)

	files, err := ghclient.FetchWorkflows(cfg.Path)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return &scanner.Result{Findings: nil, ExitCode: 0}, nil
	}

	fmt.Fprintf(os.Stderr, "Scanning %d workflow files...\n", len(files))
	return scanner.RunOnBytes(cfg, files)
}

// ---------------------------------------------------------------------------
// Changed-only scanning helper
// ---------------------------------------------------------------------------

func runChangedOnlyScan(cfg scanner.Config) (*scanner.Result, error) {
	absPath, err := filepath.Abs(cfg.Path)
	if err != nil {
		absPath = cfg.Path
	}

	if !git.IsGitRepo(absPath) {
		return nil, fmt.Errorf("--changed-only requires a git repository, but %s is not", cfg.Path)
	}

	changed, err := git.ChangedWorkflows(absPath, "")
	if err != nil {
		return nil, fmt.Errorf("detecting changed workflows: %w", err)
	}

	if len(changed) == 0 {
		fmt.Fprintln(os.Stderr, "No workflow files changed in current branch.")
		return &scanner.Result{Findings: nil, ExitCode: 0}, nil
	}

	fmt.Fprintf(os.Stderr, "Scanning %d changed workflow files...\n", len(changed))
	cfg.ChangedFiles = changed
	return scanner.Run(cfg)
}

// ---------------------------------------------------------------------------
// Config file helpers
// ---------------------------------------------------------------------------

func loadConfigFile(path string) *config.Config {
	dir := path
	if ghclient.IsRemotePath(path) {
		dir = "."
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil
	}

	cfg, err := config.Load(absDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: error loading config: %v\n", err)
		return nil
	}
	return cfg // may be nil if no config found
}

func mergeString(flag, defaultVal string, cfg *config.Config) string {
	if flag != defaultVal {
		return flag // CLI flag explicitly set
	}
	if cfg != nil {
		switch defaultVal {
		case "high":
			if cfg.FailOn != "" {
				return cfg.FailOn
			}
		case "console":
			if cfg.Format != "" {
				return cfg.Format
			}
		}
	}
	return defaultVal
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// isTTY returns true when stdout is connected to a terminal.
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
