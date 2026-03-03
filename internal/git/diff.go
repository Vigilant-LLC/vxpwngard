// Package git provides helpers for querying the local git repository,
// primarily to support the --changed-only scanning mode which restricts
// analysis to workflow files modified in the current branch.
package git

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ChangedWorkflows returns the list of workflow file paths that have been
// modified compared to the base branch. It looks for changes in
// .github/workflows/*.yml and .github/workflows/*.yaml files.
//
// dir is the repository root directory.
// baseBranch is optional -- if empty, auto-detects main/master.
func ChangedWorkflows(dir string, baseBranch string) ([]string, error) {
	if !IsGitRepo(dir) {
		return nil, fmt.Errorf("directory %s is not inside a git repository", dir)
	}

	if baseBranch == "" {
		detected, err := DetectBaseBranch(dir)
		if err != nil {
			return nil, fmt.Errorf("detecting base branch: %w", err)
		}
		baseBranch = detected
	}

	// Collect changed files from the branch diff (committed changes).
	branchFiles, err := diffNameOnly(dir, baseBranch)
	if err != nil {
		return nil, fmt.Errorf("computing branch diff against %s: %w", baseBranch, err)
	}

	// Collect staged but uncommitted changes.
	stagedFiles, err := stagedChanges(dir)
	if err != nil {
		return nil, fmt.Errorf("computing staged changes: %w", err)
	}

	// Merge and deduplicate both sets.
	merged := deduplicate(append(branchFiles, stagedFiles...))

	// Filter to workflow files and return absolute paths.
	var workflows []string
	for _, f := range merged {
		if isWorkflowFile(f) {
			workflows = append(workflows, filepath.Join(dir, f))
		}
	}

	return workflows, nil
}

// IsGitRepo returns true if the given directory is inside a git repository.
func IsGitRepo(dir string) bool {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--git-dir")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// DetectBaseBranch auto-detects the default branch (main, master, or the
// current remote HEAD).
func DetectBaseBranch(dir string) (string, error) {
	// Strategy 1: symbolic-ref of origin/HEAD.
	out, err := runGit(dir, "symbolic-ref", "refs/remotes/origin/HEAD")
	if err == nil {
		ref := strings.TrimSpace(out)
		// Strip the refs/remotes/origin/ prefix to get just the branch name.
		branch := strings.TrimPrefix(ref, "refs/remotes/origin/")
		if branch != "" {
			return branch, nil
		}
	}

	// Strategy 2: look for origin/main or origin/master in remote branches.
	out, err = runGit(dir, "branch", "-r")
	if err == nil {
		lines := strings.Split(out, "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "origin/main" {
				return "main", nil
			}
		}
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "origin/master" {
				return "master", nil
			}
		}
	}

	// Strategy 3: default to "main".
	return "main", nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// diffNameOnly returns the list of changed file paths between the base
// branch and HEAD using the three-dot diff. If the three-dot form fails
// (e.g., no common ancestor), it falls back to the two-dot form.
func diffNameOnly(dir, baseBranch string) ([]string, error) {
	// Try three-dot diff first (changes since the merge base).
	out, err := runGit(dir, "diff", "--name-only", "--diff-filter=ACMR", baseBranch+"...HEAD")
	if err != nil {
		// Fallback: two-dot diff.
		out, err = runGit(dir, "diff", "--name-only", "--diff-filter=ACMR", baseBranch)
		if err != nil {
			return nil, err
		}
	}
	return splitLines(out), nil
}

// stagedChanges returns the list of staged (cached) file paths.
func stagedChanges(dir string) ([]string, error) {
	out, err := runGit(dir, "diff", "--name-only", "--cached")
	if err != nil {
		return nil, err
	}
	return splitLines(out), nil
}

// isWorkflowFile returns true if the path matches
// .github/workflows/*.yml or .github/workflows/*.yaml.
func isWorkflowFile(path string) bool {
	// Normalise to forward slashes for consistent matching.
	p := filepath.ToSlash(path)

	dir := filepath.ToSlash(filepath.Dir(p))
	if dir != ".github/workflows" {
		return false
	}

	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yml" || ext == ".yaml"
}

// runGit executes a git command in the given directory and returns the
// combined stdout. If the command exits with a non-zero status the error
// includes the stderr output for debugging.
func runGit(dir string, args ...string) (string, error) {
	cmdArgs := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", cmdArgs...)

	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %s: %w (stderr: %s)",
				strings.Join(args, " "), err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// splitLines splits git output into non-empty lines.
func splitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// deduplicate removes duplicate strings from a slice, preserving order.
func deduplicate(items []string) []string {
	seen := make(map[string]bool, len(items))
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
