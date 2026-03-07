// VXPwngard — CI/CD Pipeline Security Scanner
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

	vxpwngard "github.com/Vigilant-LLC/vxpwngard"
	"github.com/Vigilant-LLC/vxpwngard/internal/autofix"
	"github.com/Vigilant-LLC/vxpwngard/internal/config"
	"github.com/Vigilant-LLC/vxpwngard/internal/git"
	ghclient "github.com/Vigilant-LLC/vxpwngard/internal/github"
	"github.com/Vigilant-LLC/vxpwngard/internal/reporter"
	"github.com/Vigilant-LLC/vxpwngard/internal/rules"
	"github.com/Vigilant-LLC/vxpwngard/internal/scanner"
	"github.com/Vigilant-LLC/vxpwngard/internal/tracking"
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
		newTargetsCmd(),
		newBatchCmd(),
		newImportCmd(),
		newStatsCmd(),
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
		Use:   "vxpwngard",
		Short: "VXPwngard — CI/CD Pipeline Security Scanner",
		Long: `VXPwngard detects source-to-sink injection vulnerabilities, excessive
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
		trackingDB  string
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan GitHub Actions workflows for security issues",
		Long: `Scan recursively finds .yml/.yaml files under <path>/.github/workflows/
and evaluates them against VXPwngard's built-in rule set.

Path can be:
  - A local directory:     vxpwngard scan .
  - A GitHub repository:   vxpwngard scan github.com/owner/repo
  - With a branch:         vxpwngard scan github.com/owner/repo@main`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()
			path := args[0]

			// Honour --no-color and auto-detect non-TTY.
			if noColor || !isTTY() {
				color.NoColor = true
			}

			printHeader(os.Stderr)

			// Load .vxpwngard.yaml config file.
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
				RulesFS:     vxpwngard.RulesFS,
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

			// Record results in tracking DB if --tracking-db is set.
			if trackingDB != "" && ghclient.IsRemotePath(path) {
				owner, repo, _, parseErr := ghclient.ParseRepoPath(path)
				if parseErr == nil {
					tdb, dbErr := tracking.Open(trackingDB)
					if dbErr == nil {
						defer tdb.Close()
						repoID, _ := tdb.UpsertRepo(owner, repo, 0, "")
						status := tracking.StatusCompleted
						if len(result.Findings) == 0 {
							status = tracking.StatusCompleted
						}
						scanID, _ := tdb.InsertScan(repoID, status, duration.Milliseconds(), "")
						for _, f := range result.Findings {
							tdb.InsertFinding(scanID, f.RuleID, strings.ToLower(f.Severity), f.File, f.LineNumber)
						}
					}
				}
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
	cmd.Flags().StringVar(&trackingDB, "tracking-db", "", "Record scan results in tracking database")

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
				files, err := loadDemoFiles(vxpwngard.DemoFS, sc)
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
					RulesFS:      vxpwngard.RulesFS,
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
			boldCyan.Fprintln(os.Stdout, "\u2192 Run vxpwngard scan . to check your own pipelines")

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
.vxpwngard-baseline.json. Future scans using --baseline will suppress
these findings, letting you focus on new issues.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			cfg := scanner.Config{
				Path:    path,
				Format:  "console",
				FailOn:  "critical",
				RulesFS: vxpwngard.RulesFS,
			}

			fingerprints, count, err := scanner.GenerateBaselineFingerprints(cfg)
			if err != nil {
				return fmt.Errorf("baseline scan failed: %w", err)
			}

			data, err := json.MarshalIndent(fingerprints, "", "  ")
			if err != nil {
				return fmt.Errorf("encoding baseline: %w", err)
			}

			outputPath := ".vxpwngard-baseline.json"
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
		Short: "Print VXPwngard version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stdout, "vxpwngard version v%s (commit: %s, built: %s)\n", version, commit, date)
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// printHeader prints the CLI banner to the given writer.
func printHeader(w io.Writer) {
	fmt.Fprintf(w, "VXPwngard v%s | Vigilant\n", version)
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
		"VXS-001", "VXS-002", "VXS-003", "VXS-004",
		"VXS-005", "VXS-006", "VXS-007", "VXS-008",
		"VXS-009", "VXS-010", "VXS-011", "VXS-012",
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
  VXS-002  Extract untrusted expressions from run blocks into env vars
  VXS-007  Pin third-party actions to commit SHAs
  VXS-008  Extract secrets from run blocks into env vars
  VXS-014  Extract workflow_dispatch inputs from run blocks into env vars
  VXS-015  Remove ACTIONS_RUNNER_DEBUG / ACTIONS_STEP_DEBUG env vars

Use --dry-run to preview changes without modifying files.
Use --rule to apply a specific rule's fix (e.g. --rule VXS-007).`,
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
	cmd.Flags().StringVar(&ruleFilter, "rule", "", "Apply fix for a specific rule only (e.g. VXS-007)")

	return cmd
}

// ---------------------------------------------------------------------------
// targets command
// ---------------------------------------------------------------------------

func newTargetsCmd() *cobra.Command {
	var (
		output     string
		dbPath     string
		minStars   int
		maxTargets int
		appendMode bool
	)

	cmd := &cobra.Command{
		Use:   "targets",
		Short: "Generate a target list of GitHub repos via Search API",
		Long: `Searches the GitHub Search API for repositories with GitHub Actions
workflows, partitioning by star count to overcome the 1,000 result limit.

Requires GITHUB_TOKEN environment variable for authentication.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			printHeader(os.Stderr)

			results, err := ghclient.SearchAllTiers(maxTargets, minStars, func(msg string) {
				fmt.Fprintln(os.Stderr, msg)
			})
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "\nFound %d repos total\n", len(results))

			// Write to tracking DB if --db specified.
			if dbPath != "" {
				db, err := tracking.Open(dbPath)
				if err != nil {
					return err
				}
				defer db.Close()

				imported := 0
				for _, r := range results {
					if _, err := db.UpsertRepo(r.Owner, r.Name, r.Stars, r.Language); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
						continue
					}
					imported++
				}
				fmt.Fprintf(os.Stdout, "Imported %d repos into %s\n", imported, dbPath)
			}

			// Write to TSV file.
			if output != "" {
				flags := os.O_WRONLY | os.O_CREATE
				if appendMode {
					flags |= os.O_APPEND
				} else {
					flags |= os.O_TRUNC
				}
				f, err := os.OpenFile(output, flags, 0644)
				if err != nil {
					return fmt.Errorf("opening output file: %w", err)
				}
				defer f.Close()

				if !appendMode {
					fmt.Fprintln(f, "# repo\tstars\tlanguage\tdescription")
				}
				for _, r := range results {
					fmt.Fprintf(f, "%s\t%d\t%s\t%s\n", r.FullName, r.Stars, r.Language, r.Description)
				}
				fmt.Fprintf(os.Stdout, "Wrote %d repos to %s\n", len(results), output)
			}

			// Default: print to stdout if no output specified.
			if output == "" && dbPath == "" {
				for _, r := range results {
					fmt.Fprintf(os.Stdout, "%s\t%d\t%s\n", r.FullName, r.Stars, r.Language)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output TSV file path")
	cmd.Flags().StringVar(&dbPath, "db", "", "Import results into tracking database")
	cmd.Flags().IntVar(&minStars, "min-stars", 500, "Minimum star count")
	cmd.Flags().IntVar(&maxTargets, "max-targets", 50000, "Maximum number of targets")
	cmd.Flags().BoolVar(&appendMode, "append", false, "Append to existing output file")

	return cmd
}

// ---------------------------------------------------------------------------
// batch command
// ---------------------------------------------------------------------------

func newBatchCmd() *cobra.Command {
	var (
		dbPath      string
		count       int
		delay       float64
		retryErrors bool
	)

	cmd := &cobra.Command{
		Use:   "batch",
		Short: "Batch scan repos from the tracking database",
		Long: `Reads pending (unscanned) repos from the tracking database and scans
each one via the GitHub Contents API. Results are recorded back into the DB.

Use --retry-errors to re-scan repos that previously failed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			printHeader(os.Stderr)

			db, err := tracking.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			var repos []tracking.Repo
			if retryErrors {
				repos, err = db.GetErroredRepos(count)
			} else {
				repos, err = db.GetPendingRepos(count)
			}
			if err != nil {
				return err
			}

			if len(repos) == 0 {
				fmt.Fprintln(os.Stdout, "No pending repos to scan.")
				return nil
			}

			fmt.Fprintf(os.Stderr, "Scanning %d repos...\n\n", len(repos))

			scanned, withFindings, totalFindings := 0, 0, 0

			for i, repo := range repos {
				fmt.Fprintf(os.Stderr, "[%d/%d] %s (%d\u2605)...", i+1, len(repos), repo.FullName, repo.Stars)

				start := time.Now()
				path := "github.com/" + repo.FullName

				files, fetchErr := ghclient.FetchWorkflows(path)
				if fetchErr != nil {
					duration := time.Since(start)
					db.InsertScan(repo.ID, tracking.StatusError, duration.Milliseconds(), fetchErr.Error())
					fmt.Fprintf(os.Stderr, " error: %v\n", fetchErr)
					time.Sleep(time.Duration(delay*1000) * time.Millisecond)
					continue
				}

				if len(files) == 0 {
					duration := time.Since(start)
					db.InsertScan(repo.ID, tracking.StatusNoWorkflows, duration.Milliseconds(), "")
					fmt.Fprintf(os.Stderr, " no workflows\n")
					time.Sleep(time.Duration(delay*1000) * time.Millisecond)
					continue
				}

				cfg := scanner.Config{
					Path:    path,
					Format:  "json",
					FailOn:  "critical",
					RulesFS: vxpwngard.RulesFS,
				}

				result, scanErr := scanner.RunOnBytes(cfg, files)
				duration := time.Since(start)

				if scanErr != nil {
					db.InsertScan(repo.ID, tracking.StatusError, duration.Milliseconds(), scanErr.Error())
					fmt.Fprintf(os.Stderr, " scan error: %v\n", scanErr)
					time.Sleep(time.Duration(delay*1000) * time.Millisecond)
					continue
				}

				scanID, dbErr := db.InsertScan(repo.ID, tracking.StatusCompleted, duration.Milliseconds(), "")
				if dbErr != nil {
					fmt.Fprintf(os.Stderr, " db error: %v\n", dbErr)
					continue
				}

				for _, f := range result.Findings {
					db.InsertFinding(scanID, f.RuleID, strings.ToLower(f.Severity), f.File, f.LineNumber)
				}

				scanned++
				if len(result.Findings) > 0 {
					withFindings++
					totalFindings += len(result.Findings)
				}
				fmt.Fprintf(os.Stderr, " %d findings (%.1fs)\n", len(result.Findings), duration.Seconds())

				if i < len(repos)-1 {
					time.Sleep(time.Duration(delay*1000) * time.Millisecond)
				}
			}

			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stdout, "Batch complete: %d scanned, %d with findings (%d total findings)\n",
				scanned, withFindings, totalFindings)
			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "vxpwngard-tracking.db", "Path to tracking database")
	cmd.Flags().IntVar(&count, "count", 100, "Number of repos to scan")
	cmd.Flags().Float64Var(&delay, "delay", 1.5, "Delay between scans in seconds")
	cmd.Flags().BoolVar(&retryErrors, "retry-errors", false, "Retry previously errored scans")

	return cmd
}

// ---------------------------------------------------------------------------
// import command
// ---------------------------------------------------------------------------

func newImportCmd() *cobra.Command {
	var (
		dbPath     string
		resultsDir string
		targets    string
	)

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import existing scan results into the tracking database",
		Long: `Imports repos from a targets TSV file and scan results from a directory
of JSON files into the tracking database. Used to migrate existing scan
data from the shell-based batch scanning workflow.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			printHeader(os.Stderr)

			db, err := tracking.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			// Import targets TSV if specified.
			if targets != "" {
				count, err := db.ImportTargetsTSV(targets)
				if err != nil {
					return fmt.Errorf("importing targets: %w", err)
				}
				fmt.Fprintf(os.Stdout, "Imported %d repos from %s\n", count, targets)
			}

			// Import scan results.
			if resultsDir != "" {
				count, err := db.ImportScanResults(resultsDir)
				if err != nil {
					return fmt.Errorf("importing results: %w", err)
				}
				fmt.Fprintf(os.Stdout, "Imported %d scan results from %s\n", count, resultsDir)
			}

			// Show final count.
			total, _ := db.RepoCount()
			fmt.Fprintf(os.Stdout, "Database now contains %d repos\n", total)

			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "vxpwngard-tracking.db", "Path to tracking database")
	cmd.Flags().StringVar(&resultsDir, "results-dir", "scan-results", "Directory with scan result JSON files")
	cmd.Flags().StringVar(&targets, "targets", "scan-targets.tsv", "Path to targets TSV file")

	return cmd
}

// ---------------------------------------------------------------------------
// stats command
// ---------------------------------------------------------------------------

func newStatsCmd() *cobra.Command {
	var (
		dbPath  string
		format  string
		section string
		noColor bool
	)

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Display analytics dashboard from tracking database",
		Long: `Queries the tracking database and renders a dashboard with scan
statistics, severity breakdowns, top rules, and language analysis.

The console output is designed for social media screenshots.
Use --format json for machine-readable output.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if noColor || !isTTY() {
				color.NoColor = true
			}

			db, err := tracking.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			stats, err := db.GetOverviewStats()
			if err != nil {
				return fmt.Errorf("getting stats: %w", err)
			}

			topRules, err := db.GetTopRules(15)
			if err != nil {
				return fmt.Errorf("getting top rules: %w", err)
			}

			langStats, err := db.GetLanguageStats(15)
			if err != nil {
				return fmt.Errorf("getting language stats: %w", err)
			}

			timeline, err := db.GetTimeline()
			if err != nil {
				return fmt.Errorf("getting timeline: %w", err)
			}

			if format == "json" {
				data := tracking.StatsJSON{
					Overview:  stats,
					TopRules:  topRules,
					Languages: langStats,
					Timeline:  timeline,
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(data)
			}

			// Console output.
			w := os.Stdout
			showSection := func(name string) bool {
				return section == "all" || section == name
			}

			if showSection("overview") {
				tracking.RenderOverview(w, stats)
			}
			if showSection("rules") && len(topRules) > 0 {
				tracking.RenderTopRules(w, topRules)
			}
			if showSection("languages") && len(langStats) > 0 {
				tracking.RenderLanguageStats(w, langStats)
			}
			if showSection("timeline") && len(timeline) > 0 {
				tracking.RenderTimeline(w, timeline)
			}
			fmt.Fprintln(w)

			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "vxpwngard-tracking.db", "Path to tracking database")
	cmd.Flags().StringVarP(&format, "format", "f", "console", "Output format: console, json")
	cmd.Flags().StringVar(&section, "section", "all", "Dashboard section: all, overview, rules, languages, timeline")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable ANSI color output")

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
