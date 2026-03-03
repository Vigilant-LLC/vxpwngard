package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// IsGitRepo
// ---------------------------------------------------------------------------

func TestIsGitRepo_VxpwngardRepo(t *testing.T) {
	// The vxpwngard project root is a git repository.
	repoRoot := findRepoRoot(t)
	assert.True(t, IsGitRepo(repoRoot), "vxpwngard repo root should be a git repo")
}

func TestIsGitRepo_TmpDir(t *testing.T) {
	// /tmp is (almost certainly) not a git repository.
	tmp := os.TempDir()
	assert.False(t, IsGitRepo(tmp), "/tmp should not be a git repo")
}

func TestIsGitRepo_Subdirectory(t *testing.T) {
	// A subdirectory inside the repo should also return true.
	repoRoot := findRepoRoot(t)
	subdir := filepath.Join(repoRoot, "internal")
	if _, err := os.Stat(subdir); os.IsNotExist(err) {
		t.Skip("internal/ directory does not exist")
	}
	assert.True(t, IsGitRepo(subdir), "subdirectory of a git repo should be a git repo")
}

func TestIsGitRepo_NonexistentDir(t *testing.T) {
	assert.False(t, IsGitRepo("/nonexistent-path-that-does-not-exist"))
}

// ---------------------------------------------------------------------------
// DetectBaseBranch
// ---------------------------------------------------------------------------

func TestDetectBaseBranch_ReturnsNonEmpty(t *testing.T) {
	repoRoot := findRepoRoot(t)
	branch, err := DetectBaseBranch(repoRoot)
	require.NoError(t, err)
	assert.NotEmpty(t, branch, "detected base branch should not be empty")
}

func TestDetectBaseBranch_ReasonableDefault(t *testing.T) {
	// The result should be one of the common default branch names.
	repoRoot := findRepoRoot(t)
	branch, err := DetectBaseBranch(repoRoot)
	require.NoError(t, err)

	allowed := map[string]bool{"main": true, "master": true}
	assert.True(t, allowed[branch],
		"expected base branch to be 'main' or 'master', got %q", branch)
}

// ---------------------------------------------------------------------------
// isWorkflowFile (path filtering logic)
// ---------------------------------------------------------------------------

func TestIsWorkflowFile_ValidPaths(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{".github/workflows/ci.yml", true},
		{".github/workflows/ci.yaml", true},
		{".github/workflows/deploy-prod.yml", true},
		{".github/workflows/RELEASE.YML", true},  // extension check is case-insensitive
		{".github/workflows/build.YAML", true},    // extension check is case-insensitive
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, isWorkflowFile(tt.path))
		})
	}
}

func TestIsWorkflowFile_InvalidPaths(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Wrong directory.
		{".github/ci.yml", false},
		{"workflows/ci.yml", false},
		{"src/main.go", false},
		{"README.md", false},

		// Wrong extension.
		{".github/workflows/ci.json", false},
		{".github/workflows/ci.txt", false},
		{".github/workflows/ci", false},

		// Subdirectory inside workflows (not a direct child).
		{".github/workflows/subdir/ci.yml", false},

		// Empty string.
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, isWorkflowFile(tt.path))
		})
	}
}

// ---------------------------------------------------------------------------
// splitLines
// ---------------------------------------------------------------------------

func TestSplitLines_Basic(t *testing.T) {
	input := "file1.yml\nfile2.yaml\nfile3.go\n"
	result := splitLines(input)
	assert.Equal(t, []string{"file1.yml", "file2.yaml", "file3.go"}, result)
}

func TestSplitLines_EmptyString(t *testing.T) {
	result := splitLines("")
	assert.Empty(t, result)
}

func TestSplitLines_BlankLines(t *testing.T) {
	input := "file1.yml\n\n\nfile2.yaml\n"
	result := splitLines(input)
	assert.Equal(t, []string{"file1.yml", "file2.yaml"}, result)
}

func TestSplitLines_WhitespaceOnly(t *testing.T) {
	input := "  \n  \n  "
	result := splitLines(input)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// deduplicate
// ---------------------------------------------------------------------------

func TestDeduplicate_WithDupes(t *testing.T) {
	input := []string{"a.yml", "b.yml", "a.yml", "c.yml", "b.yml"}
	result := deduplicate(input)
	assert.Equal(t, []string{"a.yml", "b.yml", "c.yml"}, result)
}

func TestDeduplicate_NoDupes(t *testing.T) {
	input := []string{"a.yml", "b.yml", "c.yml"}
	result := deduplicate(input)
	assert.Equal(t, []string{"a.yml", "b.yml", "c.yml"}, result)
}

func TestDeduplicate_Empty(t *testing.T) {
	result := deduplicate(nil)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// ChangedWorkflows (integration-level)
// ---------------------------------------------------------------------------

func TestChangedWorkflows_NotAGitRepo(t *testing.T) {
	tmp := os.TempDir()
	_, err := ChangedWorkflows(tmp, "main")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not inside a git repository")
}

func TestChangedWorkflows_ReturnsNilNotError_WhenNoChanges(t *testing.T) {
	// When the current branch IS the base branch, there are no committed
	// changes, so the result should be an empty (nil) slice with no error.
	// This test requires at least one commit to exist (HEAD must resolve).
	repoRoot := findRepoRoot(t)

	// Skip if the repository has no commits (HEAD is unresolvable).
	if _, err := runGit(repoRoot, "rev-parse", "HEAD"); err != nil {
		t.Skip("skipping: repository has no commits yet")
	}

	result, err := ChangedWorkflows(repoRoot, "HEAD")
	require.NoError(t, err)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// findRepoRoot walks up from the test file's location to find the repository
// root (directory containing go.mod).
func findRepoRoot(t *testing.T) string {
	t.Helper()

	// Start from the current working directory (test binary is run from the
	// package directory by default).
	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository root (go.mod not found)")
		}
		dir = parent
	}
}
