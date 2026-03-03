package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test: Load from temp directory
// ---------------------------------------------------------------------------

func TestLoad_FromDirectory(t *testing.T) {
	dir := t.TempDir()

	configContent := `fail-on: high
baseline: .vxpwngard-baseline.json
changed-only: true
ignore-rules:
  - VXS-007
  - VXS-008
ignore-files:
  - "experimental-*.yml"
format: json
`
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".vxpwngard.yaml"),
		[]byte(configContent),
		0644,
	))

	cfg, err := Load(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "high", cfg.FailOn)
	assert.Equal(t, ".vxpwngard-baseline.json", cfg.Baseline)
	assert.True(t, cfg.ChangedOnly)
	assert.Equal(t, []string{"VXS-007", "VXS-008"}, cfg.IgnoreRules)
	assert.Equal(t, []string{"experimental-*.yml"}, cfg.IgnoreFiles)
	assert.Equal(t, "json", cfg.Format)
}

// ---------------------------------------------------------------------------
// Test: Load with .yml extension
// ---------------------------------------------------------------------------

func TestLoad_YMLExtension(t *testing.T) {
	dir := t.TempDir()

	configContent := `fail-on: medium
`
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".vxpwngard.yml"),
		[]byte(configContent),
		0644,
	))

	cfg, err := Load(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "medium", cfg.FailOn)
}

// ---------------------------------------------------------------------------
// Test: Load prefers .yaml over .yml
// ---------------------------------------------------------------------------

func TestLoad_PrefersYAMLOverYML(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".vxpwngard.yaml"),
		[]byte("fail-on: critical\n"),
		0644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".vxpwngard.yml"),
		[]byte("fail-on: low\n"),
		0644,
	))

	cfg, err := Load(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "critical", cfg.FailOn, ".yaml should take priority over .yml")
}

// ---------------------------------------------------------------------------
// Test: Load walks up to parent directory
// ---------------------------------------------------------------------------

func TestLoad_WalksUpToParent(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "subdir")
	require.NoError(t, os.MkdirAll(child, 0755))

	require.NoError(t, os.WriteFile(
		filepath.Join(parent, ".vxpwngard.yaml"),
		[]byte("fail-on: high\n"),
		0644,
	))

	cfg, err := Load(child)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "high", cfg.FailOn)
}

// ---------------------------------------------------------------------------
// Test: Load stops at git root
// ---------------------------------------------------------------------------

func TestLoad_StopsAtGitRoot(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0755))

	// Put config ABOVE the git root (should NOT be found).
	grandparent := filepath.Dir(root)
	configPath := filepath.Join(grandparent, ".vxpwngard.yaml")
	// Only write if we can (grandparent might be read-only in CI).
	err := os.WriteFile(configPath, []byte("fail-on: low\n"), 0644)
	if err != nil {
		t.Skip("cannot write to grandparent directory")
	}
	defer os.Remove(configPath)

	child := filepath.Join(root, "src")
	require.NoError(t, os.MkdirAll(child, 0755))

	cfg, err := Load(child)
	require.NoError(t, err)
	assert.Nil(t, cfg, "should not find config above git root")
}

// ---------------------------------------------------------------------------
// Test: Load returns nil when no config file found
// ---------------------------------------------------------------------------

func TestLoad_NoConfigFile(t *testing.T) {
	dir := t.TempDir()

	// Create a .git directory so Load stops here.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0755))

	cfg, err := Load(dir)
	assert.NoError(t, err)
	assert.Nil(t, cfg, "should return nil config when no file found")
}

// ---------------------------------------------------------------------------
// Test: Load returns error for invalid YAML
// ---------------------------------------------------------------------------

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".vxpwngard.yaml"),
		[]byte("fail-on: [\ninvalid yaml"),
		0644,
	))

	_, err := Load(dir)
	assert.Error(t, err, "should return error for invalid YAML")
}

// ---------------------------------------------------------------------------
// Test: ShouldIgnoreRule
// ---------------------------------------------------------------------------

func TestShouldIgnoreRule(t *testing.T) {
	cfg := &Config{
		IgnoreRules: []string{"VXS-007", "VXS-008"},
	}

	assert.True(t, cfg.ShouldIgnoreRule("VXS-007"))
	assert.True(t, cfg.ShouldIgnoreRule("VXS-008"))
	assert.True(t, cfg.ShouldIgnoreRule("vxs-007"), "should be case-insensitive")
	assert.False(t, cfg.ShouldIgnoreRule("VXS-001"))
	assert.False(t, cfg.ShouldIgnoreRule("VXS-005"))
}

func TestShouldIgnoreRule_NilConfig(t *testing.T) {
	var cfg *Config
	assert.False(t, cfg.ShouldIgnoreRule("VXS-007"),
		"nil config should not ignore any rules")
}

func TestShouldIgnoreRule_EmptyIgnoreList(t *testing.T) {
	cfg := &Config{}
	assert.False(t, cfg.ShouldIgnoreRule("VXS-007"))
}

// ---------------------------------------------------------------------------
// Test: ShouldIgnoreFile with glob patterns
// ---------------------------------------------------------------------------

func TestShouldIgnoreFile(t *testing.T) {
	cfg := &Config{
		IgnoreFiles: []string{
			"experimental-*.yml",
			"test-*.yaml",
			"legacy.yml",
		},
	}

	tests := []struct {
		filePath   string
		wantIgnore bool
	}{
		{"experimental-feature.yml", true},
		{"experimental-test.yml", true},
		{"test-ci.yaml", true},
		{"legacy.yml", true},
		{"ci.yml", false},
		{"deploy.yaml", false},
		{"production.yml", false},
		// Full paths should also match against base name.
		{".github/workflows/experimental-feature.yml", true},
		{".github/workflows/ci.yml", false},
	}

	for _, tc := range tests {
		t.Run(tc.filePath, func(t *testing.T) {
			assert.Equal(t, tc.wantIgnore, cfg.ShouldIgnoreFile(tc.filePath),
				"ShouldIgnoreFile(%q)", tc.filePath)
		})
	}
}

func TestShouldIgnoreFile_NilConfig(t *testing.T) {
	var cfg *Config
	assert.False(t, cfg.ShouldIgnoreFile("anything.yml"),
		"nil config should not ignore any files")
}

// ---------------------------------------------------------------------------
// Test: ExtractInlineSuppressions with all supported formats
// ---------------------------------------------------------------------------

func TestExtractInlineSuppressions_AllFormats(t *testing.T) {
	content := []byte(`name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # vxpwngard:ignore
      - uses: codecov/codecov-action@v3
      - uses: docker/build-push-action@v5 # vxpwngard:ignore VXS-007
      # vxpwngard:ignore VXS-007,VXS-005
      - uses: some/action@main
      # vxpwngard:ignore VXS-007 -- we vendor this action
      - uses: vendor/action@v2
`)

	suppressions := ExtractInlineSuppressions(content, "ci.yml")

	require.Len(t, suppressions, 4)

	// 1. Bare ignore (all rules).
	assert.Equal(t, "ci.yml", suppressions[0].File)
	assert.Equal(t, 7, suppressions[0].Line)
	assert.Empty(t, suppressions[0].RuleIDs, "bare ignore should have no specific rules")
	assert.Empty(t, suppressions[0].Reason)

	// 2. Single rule ID (inline with uses line).
	assert.Equal(t, 9, suppressions[1].Line)
	assert.Equal(t, []string{"VXS-007"}, suppressions[1].RuleIDs)
	assert.Empty(t, suppressions[1].Reason)

	// 3. Multiple rule IDs.
	assert.Equal(t, 10, suppressions[2].Line)
	assert.Equal(t, []string{"VXS-007", "VXS-005"}, suppressions[2].RuleIDs)
	assert.Empty(t, suppressions[2].Reason)

	// 4. Rule ID with reason.
	assert.Equal(t, 12, suppressions[3].Line)
	assert.Equal(t, []string{"VXS-007"}, suppressions[3].RuleIDs)
	assert.Equal(t, "we vendor this action", suppressions[3].Reason)
}

func TestExtractInlineSuppressions_NoDirectives(t *testing.T) {
	content := []byte(`name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hello # just a comment
`)

	suppressions := ExtractInlineSuppressions(content, "ci.yml")
	assert.Empty(t, suppressions)
}

func TestExtractInlineSuppressions_EmptyFile(t *testing.T) {
	suppressions := ExtractInlineSuppressions([]byte{}, "empty.yml")
	assert.Empty(t, suppressions)
}

// ---------------------------------------------------------------------------
// Test: IsInlineSuppressed with exact and above-line matching
// ---------------------------------------------------------------------------

func TestIsInlineSuppressed_ExactLine(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "ci.yml", Line: 10, RuleIDs: []string{"VXS-007"}},
	}

	// Exact line match.
	assert.True(t, IsInlineSuppressed(suppressions, "VXS-007", "ci.yml", 10))

	// Different rule ID.
	assert.False(t, IsInlineSuppressed(suppressions, "VXS-001", "ci.yml", 10))

	// Different file.
	assert.False(t, IsInlineSuppressed(suppressions, "VXS-007", "deploy.yml", 10))

	// Different line.
	assert.False(t, IsInlineSuppressed(suppressions, "VXS-007", "ci.yml", 12))
}

func TestIsInlineSuppressed_LineAbove(t *testing.T) {
	// Comment on line 9 suppresses findings on line 10.
	suppressions := []InlineSuppression{
		{File: "ci.yml", Line: 9, RuleIDs: []string{"VXS-007"}},
	}

	assert.True(t, IsInlineSuppressed(suppressions, "VXS-007", "ci.yml", 10),
		"suppression on line above should apply")
	assert.False(t, IsInlineSuppressed(suppressions, "VXS-007", "ci.yml", 11),
		"suppression should not apply two lines below")
	assert.False(t, IsInlineSuppressed(suppressions, "VXS-007", "ci.yml", 8),
		"suppression should not apply to lines above the comment")
}

func TestIsInlineSuppressed_WildcardSuppression(t *testing.T) {
	// No specific rule IDs means suppress all rules.
	suppressions := []InlineSuppression{
		{File: "ci.yml", Line: 10, RuleIDs: nil},
	}

	assert.True(t, IsInlineSuppressed(suppressions, "VXS-007", "ci.yml", 10))
	assert.True(t, IsInlineSuppressed(suppressions, "VXS-001", "ci.yml", 10))
	assert.True(t, IsInlineSuppressed(suppressions, "VXS-012", "ci.yml", 10))
}

func TestIsInlineSuppressed_MultipleRuleIDs(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "ci.yml", Line: 10, RuleIDs: []string{"VXS-007", "VXS-005"}},
	}

	assert.True(t, IsInlineSuppressed(suppressions, "VXS-007", "ci.yml", 10))
	assert.True(t, IsInlineSuppressed(suppressions, "VXS-005", "ci.yml", 10))
	assert.False(t, IsInlineSuppressed(suppressions, "VXS-001", "ci.yml", 10))
}

func TestIsInlineSuppressed_CaseInsensitive(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "ci.yml", Line: 10, RuleIDs: []string{"VXS-007"}},
	}

	assert.True(t, IsInlineSuppressed(suppressions, "vxs-007", "ci.yml", 10),
		"rule ID matching should be case-insensitive")
}

func TestIsInlineSuppressed_EmptySuppressions(t *testing.T) {
	assert.False(t, IsInlineSuppressed(nil, "VXS-007", "ci.yml", 10))
	assert.False(t, IsInlineSuppressed([]InlineSuppression{}, "VXS-007", "ci.yml", 10))
}

// ---------------------------------------------------------------------------
// Test: full integration - Load config and check suppression
// ---------------------------------------------------------------------------

func TestIntegration_LoadAndCheck(t *testing.T) {
	dir := t.TempDir()

	configContent := `fail-on: high
ignore-rules:
  - VXS-007
ignore-files:
  - "experimental-*.yml"
`
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".vxpwngard.yaml"),
		[]byte(configContent),
		0644,
	))

	cfg, err := Load(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Check rule suppression.
	assert.True(t, cfg.ShouldIgnoreRule("VXS-007"))
	assert.False(t, cfg.ShouldIgnoreRule("VXS-001"))

	// Check file suppression.
	assert.True(t, cfg.ShouldIgnoreFile("experimental-feature.yml"))
	assert.False(t, cfg.ShouldIgnoreFile("ci.yml"))
}

// ---------------------------------------------------------------------------
// Test: Config with empty/default values
// ---------------------------------------------------------------------------

func TestLoad_EmptyConfig(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".vxpwngard.yaml"),
		[]byte("{}\n"),
		0644,
	))

	cfg, err := Load(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Empty(t, cfg.FailOn)
	assert.Empty(t, cfg.Baseline)
	assert.False(t, cfg.ChangedOnly)
	assert.Empty(t, cfg.IgnoreRules)
	assert.Empty(t, cfg.IgnoreFiles)
	assert.Empty(t, cfg.Format)
}
