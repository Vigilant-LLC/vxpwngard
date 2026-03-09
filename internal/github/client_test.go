package github

import (
	"net/http"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// ParseRepoPath tests
// ---------------------------------------------------------------------------

func TestParseRepoPath_BasicOwnerRepo(t *testing.T) {
	owner, repo, branch, err := ParseRepoPath("github.com/owner/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
	if branch != "" {
		t.Errorf("branch = %q, want %q", branch, "")
	}
}

func TestParseRepoPath_WithBranch(t *testing.T) {
	owner, repo, branch, err := ParseRepoPath("github.com/owner/repo@develop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
	if branch != "develop" {
		t.Errorf("branch = %q, want %q", branch, "develop")
	}
}

func TestParseRepoPath_HTTPSPrefix(t *testing.T) {
	owner, repo, branch, err := ParseRepoPath("https://github.com/Vigilant-LLC/runner-guard")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "Vigilant-LLC" {
		t.Errorf("owner = %q, want %q", owner, "Vigilant-LLC")
	}
	if repo != "runner-guard" {
		t.Errorf("repo = %q, want %q", repo, "runner-guard")
	}
	if branch != "" {
		t.Errorf("branch = %q, want %q", branch, "")
	}
}

func TestParseRepoPath_HTTPSPrefixWithBranch(t *testing.T) {
	owner, repo, branch, err := ParseRepoPath("https://github.com/owner/repo@main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
	if branch != "main" {
		t.Errorf("branch = %q, want %q", branch, "main")
	}
}

func TestParseRepoPath_TrailingSlash(t *testing.T) {
	owner, repo, _, err := ParseRepoPath("github.com/owner/repo/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
}

func TestParseRepoPath_MultipleTrailingSlashes(t *testing.T) {
	owner, repo, _, err := ParseRepoPath("github.com/owner/repo///")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
}

func TestParseRepoPath_GitSuffix(t *testing.T) {
	owner, repo, _, err := ParseRepoPath("github.com/owner/repo.git")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
}

func TestParseRepoPath_BareOwnerRepo(t *testing.T) {
	owner, repo, branch, err := ParseRepoPath("owner/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
	if branch != "" {
		t.Errorf("branch = %q, want %q", branch, "")
	}
}

func TestParseRepoPath_BareOwnerRepoWithBranch(t *testing.T) {
	owner, repo, branch, err := ParseRepoPath("owner/repo@feature/new-thing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
	if branch != "feature/new-thing" {
		t.Errorf("branch = %q, want %q", branch, "feature/new-thing")
	}
}

func TestParseRepoPath_WhitespaceHandling(t *testing.T) {
	owner, repo, _, err := ParseRepoPath("  github.com/owner/repo  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
}

func TestParseRepoPath_HTTPPrefix(t *testing.T) {
	owner, repo, _, err := ParseRepoPath("http://github.com/owner/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
}

func TestParseRepoPath_GithubProtocol(t *testing.T) {
	owner, repo, branch, err := ParseRepoPath("github://owner/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
	if branch != "" {
		t.Errorf("branch = %q, want %q", branch, "")
	}
}

func TestParseRepoPath_GithubProtocolWithBranch(t *testing.T) {
	owner, repo, branch, err := ParseRepoPath("github://owner/repo@develop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "owner" {
		t.Errorf("owner = %q, want %q", owner, "owner")
	}
	if repo != "repo" {
		t.Errorf("repo = %q, want %q", repo, "repo")
	}
	if branch != "develop" {
		t.Errorf("branch = %q, want %q", branch, "develop")
	}
}

// ---------------------------------------------------------------------------
// ParseRepoPath error cases
// ---------------------------------------------------------------------------

func TestParseRepoPath_EmptyString(t *testing.T) {
	_, _, _, err := ParseRepoPath("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestParseRepoPath_OnlyOwner(t *testing.T) {
	_, _, _, err := ParseRepoPath("github.com/owner")
	if err == nil {
		t.Fatal("expected error for path with only owner")
	}
}

func TestParseRepoPath_EmptyOwner(t *testing.T) {
	_, _, _, err := ParseRepoPath("github.com//repo")
	if err == nil {
		t.Fatal("expected error for empty owner")
	}
}

func TestParseRepoPath_EmptyRepo(t *testing.T) {
	_, _, _, err := ParseRepoPath("github.com/owner/")
	if err == nil {
		t.Fatal("expected error for empty repo")
	}
}

func TestParseRepoPath_EmptyBranchAfterAt(t *testing.T) {
	_, _, _, err := ParseRepoPath("github.com/owner/repo@")
	if err == nil {
		t.Fatal("expected error for empty branch after @")
	}
}

func TestParseRepoPath_JustGithubCom(t *testing.T) {
	_, _, _, err := ParseRepoPath("github.com/")
	if err == nil {
		t.Fatal("expected error for bare github.com/")
	}
}

func TestParseRepoPath_JustGithubComNoSlash(t *testing.T) {
	_, _, _, err := ParseRepoPath("github.com")
	if err == nil {
		t.Fatal("expected error for bare github.com")
	}
}

// ---------------------------------------------------------------------------
// IsRemotePath tests
// ---------------------------------------------------------------------------

func TestIsRemotePath_GithubComPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"github.com/owner/repo", true},
		{"github.com/owner/repo@main", true},
		{"https://github.com/owner/repo", true},
		{"https://github.com/owner/repo@branch", true},
		{"http://github.com/owner/repo", true},
		{"github://owner/repo", true},
		{"github://owner/repo@main", true},
		{"./local/path", false},
		{"/absolute/local/path", false},
		{".", false},
		{"", false},
		{"gitlab.com/owner/repo", false},
		{"bitbucket.org/owner/repo", false},
		{"owner/repo", false},
		{"  github.com/owner/repo", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsRemotePath(tt.input)
			if got != tt.want {
				t.Errorf("IsRemotePath(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isWorkflowFile tests
// ---------------------------------------------------------------------------

func TestIsWorkflowFile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"ci.yml", true},
		{"deploy.yaml", true},
		{"CI.YML", true},
		{"Build.YAML", true},
		{"readme.md", false},
		{"script.sh", false},
		{"config.json", false},
		{"", false},
		{".yml", true},
		{"workflow.yml.bak", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isWorkflowFile(tt.name)
			if got != tt.want {
				t.Errorf("isWorkflowFile(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// setCommonHeaders tests
// ---------------------------------------------------------------------------

func TestSetCommonHeaders_UserAgent(t *testing.T) {
	// Ensure GITHUB_TOKEN is unset for this test.
	originalToken := getAndClearToken(t)
	defer restoreToken(originalToken)

	req, err := newTestRequest()
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	setCommonHeaders(req)

	if got := req.Header.Get("User-Agent"); got != userAgent {
		t.Errorf("User-Agent = %q, want %q", got, userAgent)
	}
	if got := req.Header.Get("Accept"); got != "application/vnd.github.v3+json" {
		t.Errorf("Accept = %q, want %q", got, "application/vnd.github.v3+json")
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be empty when GITHUB_TOKEN is unset, got %q", got)
	}
}

func TestSetCommonHeaders_WithToken(t *testing.T) {
	originalToken := getAndClearToken(t)
	defer restoreToken(originalToken)

	t.Setenv("GITHUB_TOKEN", "ghp_testtoken123")

	req, err := newTestRequest()
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	setCommonHeaders(req)

	if got := req.Header.Get("Authorization"); got != "Bearer ghp_testtoken123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer ghp_testtoken123")
	}
}

// ---------------------------------------------------------------------------
// checkRateLimit tests
// ---------------------------------------------------------------------------

func TestCheckRateLimit_RemainingZero(t *testing.T) {
	resp := &testResponse{
		headers: map[string]string{
			"X-RateLimit-Remaining": "0",
		},
	}
	err := checkRateLimit(resp.toHTTPResponse())
	if err == nil {
		t.Fatal("expected error when rate limit remaining is 0")
	}
	if got := err.Error(); got != "GitHub API rate limit exceeded. Set GITHUB_TOKEN env var for higher limits." {
		t.Errorf("error message = %q", got)
	}
}

func TestCheckRateLimit_RemainingPositive(t *testing.T) {
	resp := &testResponse{
		headers: map[string]string{
			"X-RateLimit-Remaining": "59",
		},
	}
	err := checkRateLimit(resp.toHTTPResponse())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckRateLimit_NoHeader(t *testing.T) {
	resp := &testResponse{
		headers: map[string]string{},
	}
	err := checkRateLimit(resp.toHTTPResponse())
	if err != nil {
		t.Errorf("unexpected error when header is absent: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestRequest creates a simple GET request for testing header manipulation.
func newTestRequest() (*http.Request, error) {
	return http.NewRequest(http.MethodGet, "https://api.github.com/test", nil)
}

// testResponse is a minimal helper to build http.Response objects for testing.
type testResponse struct {
	headers map[string]string
}

func (tr *testResponse) toHTTPResponse() *http.Response {
	header := http.Header{}
	for k, v := range tr.headers {
		header.Set(k, v)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
	}
}

// getAndClearToken saves and removes the GITHUB_TOKEN env var for test isolation.
func getAndClearToken(t *testing.T) string {
	t.Helper()
	token := os.Getenv("GITHUB_TOKEN")
	t.Setenv("GITHUB_TOKEN", "")
	return token
}

// restoreToken restores the GITHUB_TOKEN env var after a test.
// Note: t.Setenv already handles cleanup, so this is a no-op safeguard
// for tests that don't use t.Setenv for the initial clear.
func restoreToken(token string) {
	if token != "" {
		os.Setenv("GITHUB_TOKEN", token)
	}
}
