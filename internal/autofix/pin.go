// Package autofix provides automated remediation for VXPwngard findings.
// Currently implements --auto-fix for VXS-007 (pinning third-party actions
// to commit SHAs).
package autofix

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PinResult describes what was changed in a single file.
type PinResult struct {
	File    string
	Action  string // e.g. "codecov/codecov-action"
	OldRef  string // e.g. "v3"
	NewRef  string // e.g. "abc123def456..." (40-char SHA)
	LineNum int
	Error   string // non-empty if this specific pin failed
}

// usesPattern matches `uses:` lines in workflow YAML, capturing the action
// reference (owner/repo) and the ref (tag/branch/SHA) after the @.
// Group 1: everything before the action (indentation, "- uses: ", etc.)
// Group 2: action reference (e.g. "codecov/codecov-action")
// Group 3: ref (e.g. "v3" or a 40-char SHA)
// Group 4: trailing content (comments, whitespace)
var usesPattern = regexp.MustCompile(`(?m)([\t ]*-?\s*uses:\s*)(\S+?)@(\S+)(.*)$`)

// shaRe validates a 40-character hexadecimal SHA.
var shaRe = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// PinActions scans workflow files in the given directory and pins all
// third-party actions (not actions/*, github/*, or ./*) to their current
// commit SHA. Returns what was changed and any errors.
//
// If dryRun is true, reports what would change without modifying files.
func PinActions(dir string, dryRun bool) ([]PinResult, error) {
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

	var results []PinResult

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

		fileResults, processErr := processFile(path, dryRun)
		if processErr != nil {
			return processErr
		}
		results = append(results, fileResults...)
		return nil
	})
	if walkErr != nil {
		return results, walkErr
	}

	return results, nil
}

// processFile reads a single workflow file, finds all third-party action
// references with mutable refs, resolves their SHAs, and optionally
// rewrites the file with pinned references.
func processFile(path string, dryRun bool) ([]PinResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("autofix: reading %s: %w", path, err)
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	var results []PinResult
	modified := false

	for i, line := range lines {
		matches := usesPattern.FindStringSubmatchIndex(line)
		if matches == nil {
			continue
		}

		// Extract the captured groups from the match.
		// Group 1: prefix (indentation + "uses: ")
		// Group 2: action reference (owner/repo or owner/repo/path)
		// Group 3: ref (tag, branch, or SHA)
		// Group 4: trailing content (comments, etc.)
		action := line[matches[4]:matches[5]]
		ref := line[matches[6]:matches[7]]
		prefix := line[matches[2]:matches[3]]

		// Skip first-party and local actions.
		lower := strings.ToLower(action)
		if strings.HasPrefix(lower, "actions/") ||
			strings.HasPrefix(lower, "github/") ||
			strings.HasPrefix(lower, "./") {
			continue
		}

		// Skip if already pinned to a 40-char SHA.
		if shaRe.MatchString(ref) {
			continue
		}

		// Parse owner/repo from the action reference (handles owner/repo/path).
		ownerRepo := parseOwnerRepo(action)
		if ownerRepo == "" {
			continue
		}

		result := PinResult{
			File:    path,
			Action:  action,
			OldRef:  ref,
			LineNum: i + 1, // 1-indexed
		}

		sha, resolveErr := ResolveActionSHA(ownerRepo, ref)
		if resolveErr != nil {
			result.Error = resolveErr.Error()
			results = append(results, result)
			continue
		}

		result.NewRef = sha

		if !dryRun {
			// Build the new line: preserve indentation, add SHA, comment with old ref.
			newLine := fmt.Sprintf("%s%s@%s # %s", prefix, action, sha, ref)
			lines[i] = newLine
			modified = true
		}

		results = append(results, result)
	}

	if modified && !dryRun {
		newContent := strings.Join(lines, "\n")
		if err := os.WriteFile(path, []byte(newContent), 0644); err != nil {
			return results, fmt.Errorf("autofix: writing %s: %w", path, err)
		}
	}

	return results, nil
}

// parseOwnerRepo extracts the "owner/repo" portion from an action reference.
// Handles formats like "owner/repo", "owner/repo/path", etc.
// Returns empty string if the format is unrecognised.
func parseOwnerRepo(action string) string {
	parts := strings.SplitN(action, "/", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

// gitRefResponse is the JSON structure returned by the GitHub git ref API.
type gitRefResponse struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
		URL  string `json:"url"`
	} `json:"object"`
}

// gitTagResponse is the JSON structure returned when dereferencing a tag object.
type gitTagResponse struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

// gitCommitResponse is the JSON structure returned by the commits endpoint.
type gitCommitResponse struct {
	SHA string `json:"sha"`
}

// ResolveActionSHA fetches the commit SHA for a given action ref.
// action is "owner/repo" and ref is the tag/branch name.
// Uses GitHub API: GET /repos/{owner}/{repo}/git/ref/tags/{ref}
// Falls back to: GET /repos/{owner}/{repo}/commits/{ref}
// Uses GITHUB_TOKEN env var if available.
func ResolveActionSHA(action string, ref string) (string, error) {
	// Try the git ref/tags endpoint first.
	sha, err := resolveViaTagRef(action, ref)
	if err == nil && sha != "" {
		return sha, nil
	}

	// Fall back to the commits endpoint (works for branches and lightweight tags).
	sha, err = resolveViaCommit(action, ref)
	if err != nil {
		return "", fmt.Errorf("resolving %s@%s: %w", action, ref, err)
	}
	return sha, nil
}

// resolveViaTagRef tries to resolve a ref via the git/ref/tags API endpoint.
// If the ref points to a tag object (annotated tag), it follows the tag to
// get the underlying commit SHA.
func resolveViaTagRef(action, ref string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/git/ref/tags/%s", action, ref)
	body, err := githubGet(url)
	if err != nil {
		return "", err
	}

	var resp gitRefResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("parsing tag ref response: %w", err)
	}

	// If the object is a commit, we have our SHA.
	if resp.Object.Type == "commit" {
		return resp.Object.SHA, nil
	}

	// If it is a tag object (annotated tag), dereference to get the commit.
	if resp.Object.Type == "tag" {
		return dereferenceTag(resp.Object.URL)
	}

	return "", fmt.Errorf("unexpected object type %q for ref %s", resp.Object.Type, ref)
}

// dereferenceTag fetches a tag object and returns the commit SHA it points to.
func dereferenceTag(tagURL string) (string, error) {
	body, err := githubGet(tagURL)
	if err != nil {
		return "", fmt.Errorf("dereferencing tag: %w", err)
	}

	var resp gitTagResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("parsing tag object: %w", err)
	}

	if resp.Object.SHA == "" {
		return "", fmt.Errorf("tag object has no commit SHA")
	}

	return resp.Object.SHA, nil
}

// resolveViaCommit resolves a ref via the commits endpoint (works for
// branches, lightweight tags, and tag names).
func resolveViaCommit(action, ref string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", action, ref)
	body, err := githubGet(url)
	if err != nil {
		return "", err
	}

	var resp gitCommitResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("parsing commit response: %w", err)
	}

	if resp.SHA == "" {
		return "", fmt.Errorf("commit response has no SHA for %s@%s", action, ref)
	}

	return resp.SHA, nil
}

// githubGet performs an authenticated GET request to the GitHub API.
// It uses the GITHUB_TOKEN environment variable for authentication when
// available, and sets a User-Agent header.
func githubGet(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", url, err)
	}

	req.Header.Set("User-Agent", "VXPwngard/0.1.0")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", url, err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("not found: %s", url)
	case http.StatusForbidden:
		return nil, fmt.Errorf("rate limited or forbidden: %s (status %d)", url, resp.StatusCode)
	default:
		return nil, fmt.Errorf("unexpected status %d from %s: %s", resp.StatusCode, url, string(body))
	}
}
