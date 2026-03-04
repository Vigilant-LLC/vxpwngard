// Package github provides functionality for fetching and scanning GitHub Actions
// workflow files from remote public repositories via the GitHub API. This enables
// vxpwngard to scan repositories without cloning them locally.
//
// Usage:
//
//	vxpwngard scan github.com/owner/repo
//	vxpwngard scan github.com/owner/repo@branch
package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// githubAPIBase is the base URL for the GitHub REST API.
	githubAPIBase = "https://api.github.com"

	// userAgent is sent with every API request.
	userAgent = "VXPwngard/0.1.0"

	// httpTimeout is the total timeout for all HTTP operations during a
	// FetchWorkflows call.
	httpTimeout = 30 * time.Second
)

// contentsEntry represents a single entry returned by the GitHub Contents API
// when listing a directory.
type contentsEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Type        string `json:"type"` // "file" or "dir"
	Size        int    `json:"size"`
	DownloadURL string `json:"download_url"`
}

// ParseRepoPath parses a string like "github.com/owner/repo" or
// "github.com/owner/repo@branch" into owner, repo, and branch components.
// If no branch is specified, branch is returned as "".
//
// Accepted formats:
//   - github.com/owner/repo
//   - github.com/owner/repo@branch
//   - https://github.com/owner/repo
//   - https://github.com/owner/repo@branch
//   - github://owner/repo
//   - github://owner/repo@branch
//   - owner/repo (bare format)
//   - owner/repo@branch
func ParseRepoPath(path string) (owner, repo, branch string, err error) {
	// Normalize the path: remove trailing slashes and whitespace.
	path = strings.TrimSpace(path)
	path = strings.TrimRight(path, "/")

	// Strip common prefixes.
	path = strings.TrimPrefix(path, "github://")
	path = strings.TrimPrefix(path, "https://")
	path = strings.TrimPrefix(path, "http://")
	path = strings.TrimPrefix(path, "github.com/")

	// At this point, path should be "owner/repo" or "owner/repo@branch".
	if path == "" {
		return "", "", "", fmt.Errorf("empty repository path")
	}

	// Split into owner and the rest (repo, possibly with @branch).
	// We use SplitN with limit 2 to keep everything after the first "/" together.
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("invalid repository path %q: expected format owner/repo", path)
	}

	owner = parts[0]
	repoAndBranch := parts[1]

	if owner == "" {
		return "", "", "", fmt.Errorf("invalid repository path %q: owner cannot be empty", path)
	}

	// Handle @branch suffix. The @ separates repo from branch, and branch
	// may contain "/" characters (e.g., "feature/new-thing").
	if idx := strings.Index(repoAndBranch, "@"); idx != -1 {
		repo = repoAndBranch[:idx]
		branch = repoAndBranch[idx+1:]
		if branch == "" {
			return "", "", "", fmt.Errorf("invalid repository path %q: branch cannot be empty after @", path)
		}
	} else {
		repo = repoAndBranch
	}

	if repo == "" {
		return "", "", "", fmt.Errorf("invalid repository path %q: repo name cannot be empty", path)
	}

	// Strip .git suffix if present.
	repo = strings.TrimSuffix(repo, ".git")

	return owner, repo, branch, nil
}

// IsRemotePath returns true if the given path looks like a GitHub remote
// repository reference. It checks for "github.com/", "https://github.com/",
// or "github://" prefixes.
func IsRemotePath(path string) bool {
	path = strings.TrimSpace(path)
	return strings.HasPrefix(path, "github.com/") ||
		strings.HasPrefix(path, "https://github.com/") ||
		strings.HasPrefix(path, "http://github.com/") ||
		strings.HasPrefix(path, "github://")
}

// FetchWorkflows fetches all workflow YAML files from a GitHub repository.
// The repoPath should be in the format "owner/repo" or "owner/repo@branch",
// optionally prefixed with "github.com/", "https://github.com/", or "github://".
//
// If the GITHUB_TOKEN environment variable is set, it is used for
// authentication, which provides higher API rate limits (5,000 vs 60
// requests per hour for unauthenticated requests).
//
// Returns a map of filename -> file content bytes. Only files ending in
// .yml or .yaml are included. Returns an empty map (not an error) when
// the repository has no .github/workflows directory.
func FetchWorkflows(repoPath string) (map[string][]byte, error) {
	owner, repo, branch, err := ParseRepoPath(repoPath)
	if err != nil {
		return nil, fmt.Errorf("parsing repository path: %w", err)
	}

	client := &http.Client{
		Timeout: httpTimeout,
	}

	// Build the URL for the Contents API to list .github/workflows.
	listURL := fmt.Sprintf("%s/repos/%s/%s/contents/.github/workflows", githubAPIBase, owner, repo)
	if branch != "" {
		listURL += "?ref=" + branch
	}

	// Fetch the directory listing.
	entries, err := fetchDirectoryListing(client, listURL, owner, repo)
	if err != nil {
		return nil, err
	}

	// Filter to only .yml and .yaml files and fetch their content.
	workflows := make(map[string][]byte)
	for _, entry := range entries {
		if entry.Type != "file" {
			continue
		}
		if !isWorkflowFile(entry.Name) {
			continue
		}

		content, err := fetchFileContent(client, entry.DownloadURL, entry.Name, owner, repo)
		if err != nil {
			return nil, fmt.Errorf("fetching workflow file %s: %w", entry.Name, err)
		}
		workflows[entry.Name] = content
	}

	return workflows, nil
}

// fetchDirectoryListing performs a GET request to the GitHub Contents API to
// list the contents of the .github/workflows directory.
func fetchDirectoryListing(client *http.Client, url, owner, repo string) ([]contentsEntry, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s/%s workflow listing: %w", owner, repo, err)
	}
	setCommonHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching workflow listing for %s/%s: %w", owner, repo, err)
	}
	defer resp.Body.Close()

	// Check rate limit before processing the response.
	if err := checkRateLimit(resp); err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// Success — parse the JSON response.
	case http.StatusNotFound:
		// 404 means the repo has no .github/workflows directory (or the repo
		// itself doesn't exist). Return an empty slice so the caller can
		// distinguish "nothing to scan" from a real error.
		return nil, nil
	case http.StatusForbidden:
		return nil, fmt.Errorf("access denied for %s/%s: the repository may be private, or the GitHub API rate limit has been exceeded; set GITHUB_TOKEN env var for higher limits", owner, repo)
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GitHub API returned status %d for %s/%s: %s", resp.StatusCode, owner, repo, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading workflow listing response for %s/%s: %w", owner, repo, err)
	}

	var entries []contentsEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parsing workflow listing for %s/%s: %w", owner, repo, err)
	}

	return entries, nil
}

// fetchFileContent downloads the raw content of a single file using its
// download_url from the GitHub Contents API response.
func fetchFileContent(client *http.Client, downloadURL, filename, owner, repo string) ([]byte, error) {
	if downloadURL == "" {
		return nil, fmt.Errorf("no download URL available for %s in %s/%s", filename, owner, repo)
	}

	req, err := http.NewRequest(http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", filename, err)
	}
	setCommonHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", filename, err)
	}
	defer resp.Body.Close()

	// Check rate limit on file download responses too.
	if err := checkRateLimit(resp); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("downloading %s returned status %d: %s", filename, resp.StatusCode, string(body))
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading content of %s: %w", filename, err)
	}

	return content, nil
}

// setCommonHeaders applies standard headers to every GitHub API request,
// including the User-Agent, Accept header, and optional Bearer token.
func setCommonHeaders(req *http.Request) {
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// checkRateLimit inspects the X-RateLimit-Remaining response header and
// returns an error if the rate limit has been exhausted.
func checkRateLimit(resp *http.Response) error {
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	if remaining == "0" {
		return fmt.Errorf("GitHub API rate limit exceeded. Set GITHUB_TOKEN env var for higher limits.")
	}
	return nil
}

// isWorkflowFile returns true if the filename has a .yml or .yaml extension.
func isWorkflowFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}
