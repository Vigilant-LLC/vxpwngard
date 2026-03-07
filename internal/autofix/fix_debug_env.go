package autofix

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// debugVars are the environment variable names that enable verbose runner logging.
var debugVars = []string{"ACTIONS_RUNNER_DEBUG", "ACTIONS_STEP_DEBUG"}

// FixDebugEnvVars removes ACTIONS_RUNNER_DEBUG and ACTIONS_STEP_DEBUG entries
// (set to true) from env blocks in workflow files. Fixes VXS-015.
func FixDebugEnvVars(dir string, dryRun bool) ([]FixResult, error) {
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
		fileResults, processErr := processFileDebugRemoval(path, dryRun)
		if processErr != nil {
			return processErr
		}
		results = append(results, fileResults...)
		return nil
	})
	return results, walkErr
}

// processFileDebugRemoval removes debug env var entries from a single file.
func processFileDebugRemoval(path string, dryRun bool) ([]FixResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	var results []FixResult
	var linesToRemove []int

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isDebugEnvEntry(trimmed) {
			linesToRemove = append(linesToRemove, i)
			key := extractEnvKey(trimmed)
			results = append(results, FixResult{
				File:    path,
				RuleID:  "VXS-015",
				Detail:  "Removed " + key + " from env block",
				LineNum: i + 1,
			})
		}
	}

	if len(linesToRemove) == 0 {
		return nil, nil
	}

	if !dryRun {
		// Remove lines in reverse order to preserve indices.
		for j := len(linesToRemove) - 1; j >= 0; j-- {
			idx := linesToRemove[j]
			lines = append(lines[:idx], lines[idx+1:]...)
		}

		// Remove any env: keys that are now empty.
		lines = removeEmptyEnvBlocks(lines)

		newContent := strings.Join(lines, "\n")
		if writeErr := os.WriteFile(path, []byte(newContent), 0644); writeErr != nil {
			return results, fmt.Errorf("writing %s: %w", path, writeErr)
		}
	}

	return results, nil
}

// isDebugEnvEntry checks if a trimmed line is a debug env variable set to true.
func isDebugEnvEntry(trimmed string) bool {
	for _, dv := range debugVars {
		if !strings.HasPrefix(strings.ToUpper(trimmed), dv+":") {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) == 2 {
			val := strings.TrimSpace(parts[1])
			if strings.EqualFold(val, "true") {
				return true
			}
		}
	}
	return false
}

// extractEnvKey returns the key name from a "KEY: value" line.
func extractEnvKey(trimmed string) string {
	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}
	return trimmed
}

// removeEmptyEnvBlocks removes env: keys that have no content entries beneath them.
func removeEmptyEnvBlocks(lines []string) []string {
	var toRemove []int
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "env:" {
			continue
		}

		indent := countIndent(line)
		contentIndent := indent + 2

		// Check if there are content lines after this env: key.
		hasContent := false
		for j := i + 1; j < len(lines); j++ {
			nextTrimmed := strings.TrimSpace(lines[j])
			if nextTrimmed == "" {
				continue
			}
			if countIndent(lines[j]) >= contentIndent {
				hasContent = true
			}
			break
		}

		if !hasContent {
			toRemove = append(toRemove, i)
		}
	}

	// Remove in reverse order.
	for j := len(toRemove) - 1; j >= 0; j-- {
		idx := toRemove[j]
		lines = append(lines[:idx], lines[idx+1:]...)
	}

	return lines
}
