// Package config implements .runner-guard.yaml configuration file loading and
// inline # runner-guard:ignore suppression parsing for Runner Guard.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents a .runner-guard.yaml configuration file.
type Config struct {
	FailOn      string   `yaml:"fail-on"`
	Baseline    string   `yaml:"baseline"`
	ChangedOnly bool     `yaml:"changed-only"`
	IgnoreRules []string `yaml:"ignore-rules"`
	IgnoreFiles []string `yaml:"ignore-files"`
	Format      string   `yaml:"format"`
}

// configFileNames lists the filenames we search for, in priority order.
var configFileNames = []string{".runner-guard.yaml", ".runner-guard.yml"}

// Load searches for .runner-guard.yaml (or .runner-guard.yml) in the given
// directory and its parent directories (up to the git root or filesystem root).
// Returns nil config (not error) if no config file is found.
func Load(dir string) (*Config, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("config: resolving path %s: %w", dir, err)
	}

	current := absDir
	for {
		for _, name := range configFileNames {
			candidate := filepath.Join(current, name)
			data, err := os.ReadFile(candidate)
			if err == nil {
				cfg := &Config{}
				if err := yaml.Unmarshal(data, cfg); err != nil {
					return nil, fmt.Errorf("config: parsing %s: %w", candidate, err)
				}
				return cfg, nil
			}
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("config: reading %s: %w", candidate, err)
			}
		}

		// Stop if we have reached a git root (contains .git).
		gitDir := filepath.Join(current, ".git")
		if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
			break
		}

		// Move up one directory.
		parent := filepath.Dir(current)
		if parent == current {
			// Reached filesystem root.
			break
		}
		current = parent
	}

	return nil, nil
}

// ShouldIgnoreRule returns true if the rule ID is in the ignore list.
func (c *Config) ShouldIgnoreRule(ruleID string) bool {
	if c == nil {
		return false
	}
	for _, id := range c.IgnoreRules {
		if strings.EqualFold(id, ruleID) {
			return true
		}
	}
	return false
}

// ShouldIgnoreFile returns true if the file path matches any ignore pattern.
// Supports glob patterns like "experimental-*.yml".
func (c *Config) ShouldIgnoreFile(filePath string) bool {
	if c == nil {
		return false
	}
	base := filepath.Base(filePath)
	for _, pattern := range c.IgnoreFiles {
		// Try matching against the full path first.
		if matched, _ := filepath.Match(pattern, filePath); matched {
			return true
		}
		// Also try matching against just the base filename.
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}
	return false
}

// InlineSuppression represents a # runner-guard:ignore directive found in YAML.
type InlineSuppression struct {
	File    string
	Line    int
	RuleIDs []string // empty means "ignore all rules on this line"
	Reason  string   // optional: text after the rule IDs
}

// inlineIgnorePattern matches the # runner-guard:ignore directive in comments.
// It captures:
//   - Group 1: everything after "runner-guard:ignore" (rule IDs, reason, etc.)
var inlineIgnorePattern = regexp.MustCompile(`#\s*runner-guard:ignore\b(.*)`)

// ruleIDPattern matches RGS-NNN style rule identifiers.
var ruleIDPattern = regexp.MustCompile(`RGS-\d+`)

// ExtractInlineSuppressions scans a YAML file's raw bytes for
// # runner-guard:ignore directives and returns all found suppressions.
//
// Supported formats:
//
//	# runner-guard:ignore
//	# runner-guard:ignore RGS-007
//	# runner-guard:ignore RGS-007,RGS-005
//	# runner-guard:ignore RGS-007 -- we vendor this action
func ExtractInlineSuppressions(data []byte, filePath string) []InlineSuppression {
	var suppressions []InlineSuppression

	lines := bytes.Split(data, []byte("\n"))
	for i, line := range lines {
		lineStr := string(line)
		matches := inlineIgnorePattern.FindStringSubmatch(lineStr)
		if matches == nil {
			continue
		}

		sup := InlineSuppression{
			File: filePath,
			Line: i + 1, // 1-indexed
		}

		remainder := strings.TrimSpace(matches[1])
		if remainder != "" {
			// Split on " -- " to separate rule IDs from reason.
			parts := strings.SplitN(remainder, "--", 2)
			rulesPart := strings.TrimSpace(parts[0])
			if len(parts) == 2 {
				sup.Reason = strings.TrimSpace(parts[1])
			}

			// Extract rule IDs from the rules part.
			if rulesPart != "" {
				ruleIDs := ruleIDPattern.FindAllString(rulesPart, -1)
				sup.RuleIDs = ruleIDs
			}
		}

		suppressions = append(suppressions, sup)
	}

	return suppressions
}

// IsInlineSuppressed returns true if a finding at the given file and line
// is suppressed by any inline directive (checks the finding line and the
// line above it, since comments typically precede the flagged line).
func IsInlineSuppressed(suppressions []InlineSuppression, ruleID string, filePath string, lineNumber int) bool {
	for _, sup := range suppressions {
		// Must be the same file.
		if sup.File != filePath {
			continue
		}

		// The suppression must be on the same line or the line directly above.
		if sup.Line != lineNumber && sup.Line != lineNumber-1 {
			continue
		}

		// If no specific rule IDs are listed, suppress all rules.
		if len(sup.RuleIDs) == 0 {
			return true
		}

		// Check if the specific rule ID is listed.
		for _, id := range sup.RuleIDs {
			if strings.EqualFold(id, ruleID) {
				return true
			}
		}
	}

	return false
}
