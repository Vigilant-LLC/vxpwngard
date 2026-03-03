package autofix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test: usesPattern regex parsing
// ---------------------------------------------------------------------------

func TestUsesPatternParsing(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantAction string
		wantRef    string
		wantMatch  bool
	}{
		{
			name:       "standard action reference",
			line:       "      - uses: codecov/codecov-action@v3",
			wantAction: "codecov/codecov-action",
			wantRef:    "v3",
			wantMatch:  true,
		},
		{
			name:       "action with path",
			line:       "      - uses: aws-actions/configure-aws-credentials@v4",
			wantAction: "aws-actions/configure-aws-credentials",
			wantRef:    "v4",
			wantMatch:  true,
		},
		{
			name:       "action pinned to SHA",
			line:       "      - uses: codecov/codecov-action@abc123def456abc123def456abc123def456abcd",
			wantAction: "codecov/codecov-action",
			wantRef:    "abc123def456abc123def456abc123def456abcd",
			wantMatch:  true,
		},
		{
			name:       "action with trailing comment",
			line:       "      - uses: codecov/codecov-action@v3 # upload coverage",
			wantAction: "codecov/codecov-action",
			wantRef:    "v3",
			wantMatch:  true,
		},
		{
			name:      "run step not uses",
			line:      "      - run: echo hello",
			wantMatch: false,
		},
		{
			name:       "uses with tab indent",
			line:       "\t\t- uses: some-org/some-action@main",
			wantAction: "some-org/some-action",
			wantRef:    "main",
			wantMatch:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := usesPattern.FindStringSubmatch(tc.line)
			if !tc.wantMatch {
				assert.Nil(t, matches, "expected no match for: %s", tc.line)
				return
			}
			require.NotNil(t, matches, "expected match for: %s", tc.line)
			assert.Equal(t, tc.wantAction, matches[2])
			assert.Equal(t, tc.wantRef, matches[3])
		})
	}
}

// ---------------------------------------------------------------------------
// Test: identifying third-party vs first-party actions
// ---------------------------------------------------------------------------

func TestIsFirstPartyOrLocal(t *testing.T) {
	tests := []struct {
		action    string
		wantSkip  bool
		rationale string
	}{
		{"actions/checkout", true, "actions/* is first-party"},
		{"actions/setup-node", true, "actions/* is first-party"},
		{"github/codeql-action/init", true, "github/* is first-party"},
		{"./my-local-action", true, "local action should be skipped"},
		{"codecov/codecov-action", false, "third-party action"},
		{"aws-actions/configure-aws-credentials", false, "third-party action"},
		{"docker/build-push-action", false, "third-party action"},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			lower := strings.ToLower(tc.action)
			isSkipped := strings.HasPrefix(lower, "actions/") ||
				strings.HasPrefix(lower, "github/") ||
				strings.HasPrefix(lower, "./")
			assert.Equal(t, tc.wantSkip, isSkipped, tc.rationale)
		})
	}
}

// ---------------------------------------------------------------------------
// Test: parseOwnerRepo
// ---------------------------------------------------------------------------

func TestParseOwnerRepo(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"codecov/codecov-action", "codecov/codecov-action"},
		{"aws-actions/configure-aws-credentials", "aws-actions/configure-aws-credentials"},
		{"github/codeql-action/init", "github/codeql-action"},
		{"just-a-name", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseOwnerRepo(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Test: SHA format validation
// ---------------------------------------------------------------------------

func TestSHAFormatValidation(t *testing.T) {
	tests := []struct {
		ref     string
		isSHA   bool
	}{
		{"v3", false},
		{"main", false},
		{"release/v2", false},
		{"abc123", false},
		{"abc123def456abc123def456abc123def456abcd", true},  // exactly 40 hex chars
		{"ABC123DEF456ABC123DEF456ABC123DEF456ABCD", true},  // uppercase is valid
		{"abc123def456abc123def456abc123def456abc", false},   // 39 chars, too short
		{"abc123def456abc123def456abc123def456abcde", false}, // 41 chars, too long
		{"xyz123def456abc123def456abc123def456abcd", false},  // non-hex chars
	}

	for _, tc := range tests {
		t.Run(tc.ref, func(t *testing.T) {
			assert.Equal(t, tc.isSHA, shaRe.MatchString(tc.ref),
				"SHA validation for %q", tc.ref)
		})
	}
}

// ---------------------------------------------------------------------------
// Test: PinActions dry run mode (no file modification)
// ---------------------------------------------------------------------------

func TestPinActions_DryRun_NoFileModification(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(wfDir, 0755))

	workflowContent := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: codecov/codecov-action@v3
      - uses: docker/build-push-action@v5
`
	wfPath := filepath.Join(wfDir, "ci.yml")
	require.NoError(t, os.WriteFile(wfPath, []byte(workflowContent), 0644))

	// Read original content for comparison.
	originalContent, err := os.ReadFile(wfPath)
	require.NoError(t, err)

	// PinActions in dry run will fail on ResolveActionSHA (no network),
	// but the file should remain unchanged.
	_, _ = PinActions(dir, true)

	afterContent, err := os.ReadFile(wfPath)
	require.NoError(t, err)
	assert.Equal(t, string(originalContent), string(afterContent),
		"file should not be modified in dry run mode")
}

// ---------------------------------------------------------------------------
// Test: PinActions with no workflows directory
// ---------------------------------------------------------------------------

func TestPinActions_NoWorkflowsDir(t *testing.T) {
	dir := t.TempDir()

	results, err := PinActions(dir, false)
	assert.NoError(t, err)
	assert.Nil(t, results, "no results expected when .github/workflows does not exist")
}

// ---------------------------------------------------------------------------
// Test: PinActions skips first-party actions
// ---------------------------------------------------------------------------

func TestPinActions_SkipsFirstParty(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(wfDir, 0755))

	// Workflow with only first-party actions (should produce no results).
	workflowContent := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - uses: github/codeql-action/init@v3
`
	wfPath := filepath.Join(wfDir, "ci.yml")
	require.NoError(t, os.WriteFile(wfPath, []byte(workflowContent), 0644))

	results, err := PinActions(dir, true)
	assert.NoError(t, err)
	assert.Empty(t, results, "first-party actions should be skipped")
}

// ---------------------------------------------------------------------------
// Test: PinActions skips already-pinned actions
// ---------------------------------------------------------------------------

func TestPinActions_SkipsAlreadyPinned(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(wfDir, 0755))

	sha := "abc123def456abc123def456abc123def456abcd"
	workflowContent := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: codecov/codecov-action@` + sha + ` # v3
`
	wfPath := filepath.Join(wfDir, "ci.yml")
	require.NoError(t, os.WriteFile(wfPath, []byte(workflowContent), 0644))

	results, err := PinActions(dir, true)
	assert.NoError(t, err)
	assert.Empty(t, results, "already-pinned actions should be skipped")
}

// ---------------------------------------------------------------------------
// Test: PinActions identifies unpinned third-party actions
// ---------------------------------------------------------------------------

func TestPinActions_IdentifiesUnpinnedThirdParty(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(wfDir, 0755))

	workflowContent := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: codecov/codecov-action@v3
      - uses: docker/build-push-action@v5
      - uses: some-org/some-action@main
`
	wfPath := filepath.Join(wfDir, "ci.yml")
	require.NoError(t, os.WriteFile(wfPath, []byte(workflowContent), 0644))

	// Dry run: will attempt to resolve SHAs (which will fail without network)
	// but should identify the third-party actions.
	results, _ := PinActions(dir, true)

	// Should have results for the 3 third-party actions.
	assert.Len(t, results, 3, "expected 3 third-party action results")

	// Verify the actions found.
	actions := make(map[string]bool)
	for _, r := range results {
		actions[r.Action] = true
		assert.NotEmpty(t, r.OldRef, "old ref should be populated")
	}
	assert.True(t, actions["codecov/codecov-action"], "should find codecov action")
	assert.True(t, actions["docker/build-push-action"], "should find docker action")
	assert.True(t, actions["some-org/some-action"], "should find some-org action")
}

// ---------------------------------------------------------------------------
// Test: processFile with multiple workflow files
// ---------------------------------------------------------------------------

func TestPinActions_MultipleWorkflowFiles(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(wfDir, 0755))

	wf1 := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: codecov/codecov-action@v3
`
	wf2 := `name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@v5
`
	require.NoError(t, os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(wf1), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(wfDir, "deploy.yaml"), []byte(wf2), 0644))

	results, _ := PinActions(dir, true)
	assert.Len(t, results, 2, "expected results from both workflow files")

	files := make(map[string]bool)
	for _, r := range results {
		files[filepath.Base(r.File)] = true
	}
	assert.True(t, files["ci.yml"])
	assert.True(t, files["deploy.yaml"])
}

// ---------------------------------------------------------------------------
// Test: PinResult fields are populated correctly
// ---------------------------------------------------------------------------

func TestPinResult_FieldPopulation(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(wfDir, 0755))

	workflowContent := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: codecov/codecov-action@v3
`
	wfPath := filepath.Join(wfDir, "ci.yml")
	require.NoError(t, os.WriteFile(wfPath, []byte(workflowContent), 0644))

	results, _ := PinActions(dir, true)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, wfPath, r.File)
	assert.Equal(t, "codecov/codecov-action", r.Action)
	assert.Equal(t, "v3", r.OldRef)
	assert.Equal(t, 8, r.LineNum, "line number should be 1-indexed")
}
