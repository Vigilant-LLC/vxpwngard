package autofix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupWorkflowFile creates a temporary directory with a workflow file for testing.
func setupWorkflowFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(wfDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(wfDir, "test.yml"), []byte(content), 0644))
	return dir
}

// readWorkflowFile reads back the workflow file after a fix.
func readWorkflowFile(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "test.yml"))
	require.NoError(t, err)
	return string(data)
}

// tier1Matcher matches Tier-1 untrusted sources.
func tier1Matcher(expr string) bool {
	lower := strings.ToLower(expr)
	for _, src := range tier1Sources {
		if strings.Contains(lower, strings.ToLower(src)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Env extraction tests
// ---------------------------------------------------------------------------

func TestEnvExtract_SingleLineRun(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Echo title
        run: echo "${{ github.event.pull_request.title }}"
`)

	results, err := ExtractExpressionsToEnv(dir, tier1Matcher, "RGS-002", false)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "RGS-002", results[0].RuleID)

	content := readWorkflowFile(t, dir)
	assert.Contains(t, content, "${PR_TITLE}")
	assert.Contains(t, content, "PR_TITLE: ${{ github.event.pull_request.title }}")
	assert.NotContains(t, content, `run: echo "${{ github.event.pull_request.title }}"`)
}

func TestEnvExtract_MultiLineRun(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build
        run: |
          echo "Branch: ${{ github.head_ref }}"
          echo "Title: ${{ github.event.pull_request.title }}"
`)

	results, err := ExtractExpressionsToEnv(dir, tier1Matcher, "RGS-002", false)
	require.NoError(t, err)
	assert.Len(t, results, 2)

	content := readWorkflowFile(t, dir)
	assert.Contains(t, content, "${HEAD_REF}")
	assert.Contains(t, content, "${PR_TITLE}")
	assert.Contains(t, content, "HEAD_REF: ${{ github.head_ref }}")
	assert.Contains(t, content, "PR_TITLE: ${{ github.event.pull_request.title }}")
}

func TestEnvExtract_ExistingEnvBlock(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: echo "${{ github.event.pull_request.title }}"
        env:
          NODE_ENV: production
`)

	results, err := ExtractExpressionsToEnv(dir, tier1Matcher, "RGS-002", false)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	content := readWorkflowFile(t, dir)
	assert.Contains(t, content, "${PR_TITLE}")
	assert.Contains(t, content, "NODE_ENV: production")
	assert.Contains(t, content, "PR_TITLE: ${{ github.event.pull_request.title }}")
}

func TestEnvExtract_DryRunNoModification(t *testing.T) {
	original := `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
`
	dir := setupWorkflowFile(t, original)

	results, err := ExtractExpressionsToEnv(dir, tier1Matcher, "RGS-002", true)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	content := readWorkflowFile(t, dir)
	assert.Equal(t, original, content, "dry run should not modify the file")
}

func TestEnvExtract_NoMatchingExpressions(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.sha }}"
`)

	results, err := ExtractExpressionsToEnv(dir, tier1Matcher, "RGS-002", false)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestEnvExtract_SecretsInRun(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: |
          curl -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}" https://api.example.com
`)

	secretsMatcher := func(expr string) bool {
		lower := strings.ToLower(expr)
		return strings.Contains(lower, "secrets.") || strings.Contains(lower, "github.token")
	}

	results, err := ExtractExpressionsToEnv(dir, secretsMatcher, "RGS-008", false)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	content := readWorkflowFile(t, dir)
	assert.Contains(t, content, "${DEPLOY_TOKEN}")
	assert.Contains(t, content, "DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}")
}

func TestEnvExtract_DispatchInput(t *testing.T) {
	dir := setupWorkflowFile(t, `name: Deploy
on:
  workflow_dispatch:
    inputs:
      version:
        description: 'Version'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying ${{ github.event.inputs.version }}"
`)

	inputMatcher := func(expr string) bool {
		return strings.Contains(strings.ToLower(expr), "github.event.inputs.")
	}

	results, err := ExtractExpressionsToEnv(dir, inputMatcher, "RGS-014", false)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	content := readWorkflowFile(t, dir)
	assert.Contains(t, content, "${INPUT_VERSION}")
	assert.Contains(t, content, "INPUT_VERSION: ${{ github.event.inputs.version }}")
}

// ---------------------------------------------------------------------------
// Single-quote safety tests (P0)
// ---------------------------------------------------------------------------

func TestEnvExtract_SkipsSingleQuotedExpressions(t *testing.T) {
	original := `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ github.event.pull_request.title }}'
`
	dir := setupWorkflowFile(t, original)

	results, err := ExtractExpressionsToEnv(dir, tier1Matcher, "RGS-002", false)
	require.NoError(t, err)
	assert.Empty(t, results, "should not extract expressions inside single quotes")

	content := readWorkflowFile(t, dir)
	assert.Equal(t, original, content, "file should not be modified")
}

func TestEnvExtract_MixedQuotesExtractsDoubleQuotedOnly(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo '${{ github.event.pull_request.title }}'
          echo "${{ github.head_ref }}"
`)

	results, err := ExtractExpressionsToEnv(dir, tier1Matcher, "RGS-002", false)
	require.NoError(t, err)
	assert.Len(t, results, 1, "should only extract the double-quoted expression")

	content := readWorkflowFile(t, dir)
	assert.Contains(t, content, "${HEAD_REF}")
	assert.Contains(t, content, "${{ github.event.pull_request.title }}", "single-quoted expr should remain untouched")
}

// ---------------------------------------------------------------------------
// Compound expression env var name tests (P1)
// ---------------------------------------------------------------------------

func TestDeriveEnvVarName_CompoundExpression(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"toJSON(github.event.pull_request.body)", "PR_BODY"},
		{"format('{0}', github.head_ref)", "HEAD_REF"},
		{"github.event.issue.title || 'default'", "ISSUE_TITLE"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			path := extractContextPath("${{ " + tt.input + " }}")
			result := deriveEnvVarName(path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Debug env quoted true tests (P1)
// ---------------------------------------------------------------------------

func TestFixDebugEnv_RemovesQuotedTrue(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

env:
  ACTIONS_RUNNER_DEBUG: 'true'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`)

	results, err := FixDebugEnvVars(dir, false)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	content := readWorkflowFile(t, dir)
	assert.NotContains(t, content, "ACTIONS_RUNNER_DEBUG")
}

func TestFixDebugEnv_RemovesDoubleQuotedTrue(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

env:
  ACTIONS_STEP_DEBUG: "true"

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`)

	results, err := FixDebugEnvVars(dir, false)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	content := readWorkflowFile(t, dir)
	assert.NotContains(t, content, "ACTIONS_STEP_DEBUG")
}

// ---------------------------------------------------------------------------
// Block scalar indicator tests (P2)
// ---------------------------------------------------------------------------

func TestEnvExtract_BlockScalarWithIndentIndicator(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |2
          echo "${{ github.event.pull_request.title }}"
`)

	results, err := ExtractExpressionsToEnv(dir, tier1Matcher, "RGS-002", false)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	content := readWorkflowFile(t, dir)
	assert.Contains(t, content, "${PR_TITLE}")
	assert.Contains(t, content, "PR_TITLE: ${{ github.event.pull_request.title }}")
}

// ---------------------------------------------------------------------------
// Env var name derivation tests
// ---------------------------------------------------------------------------

func TestDeriveEnvVarName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"github.head_ref", "HEAD_REF"},
		{"github.event.pull_request.title", "PR_TITLE"},
		{"github.event.pull_request.body", "PR_BODY"},
		{"github.event.issue.title", "ISSUE_TITLE"},
		{"github.event.issue.body", "ISSUE_BODY"},
		{"github.event.comment.body", "COMMENT_BODY"},
		{"secrets.DEPLOY_KEY", "DEPLOY_KEY"},
		{"secrets.npm_token", "NPM_TOKEN"},
		{"github.token", "GITHUB_TOKEN"},
		{"github.event.inputs.version", "INPUT_VERSION"},
		{"github.event.inputs.tag_name", "INPUT_TAG_NAME"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := deriveEnvVarName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Debug env removal tests
// ---------------------------------------------------------------------------

func TestFixDebugEnv_RemovesRunnerDebug(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

env:
  ACTIONS_RUNNER_DEBUG: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`)

	results, err := FixDebugEnvVars(dir, false)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	content := readWorkflowFile(t, dir)
	assert.NotContains(t, content, "ACTIONS_RUNNER_DEBUG")
}

func TestFixDebugEnv_RemovesStepDebug(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      ACTIONS_STEP_DEBUG: true
      NODE_ENV: production
    steps:
      - run: echo "hello"
`)

	results, err := FixDebugEnvVars(dir, false)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	content := readWorkflowFile(t, dir)
	assert.NotContains(t, content, "ACTIONS_STEP_DEBUG")
	assert.Contains(t, content, "NODE_ENV: production")
}

func TestFixDebugEnv_KeepsFalse(t *testing.T) {
	original := `name: CI
on: push

env:
  ACTIONS_RUNNER_DEBUG: false

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`
	dir := setupWorkflowFile(t, original)

	results, err := FixDebugEnvVars(dir, false)
	require.NoError(t, err)
	assert.Empty(t, results)

	content := readWorkflowFile(t, dir)
	assert.Equal(t, original, content)
}

func TestFixDebugEnv_RemovesEmptyEnvBlock(t *testing.T) {
	dir := setupWorkflowFile(t, `name: CI
on: push

env:
  ACTIONS_RUNNER_DEBUG: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`)

	_, err := FixDebugEnvVars(dir, false)
	require.NoError(t, err)

	content := readWorkflowFile(t, dir)
	// The env: key should be removed since it's now empty.
	assert.NotContains(t, content, "env:")
}

func TestFixDebugEnv_DryRunNoChange(t *testing.T) {
	original := `name: CI
on: push

env:
  ACTIONS_RUNNER_DEBUG: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`
	dir := setupWorkflowFile(t, original)

	results, err := FixDebugEnvVars(dir, true)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	content := readWorkflowFile(t, dir)
	assert.Equal(t, original, content, "dry run should not modify the file")
}
