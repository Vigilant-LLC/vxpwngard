package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Vigilant-LLC/vxpwngard/internal/parser"
)

// helper to parse inline YAML and return a workflow.
func mustParseWorkflow(t *testing.T, name string, yamlContent string) *parser.Workflow {
	t.Helper()
	wf, err := parser.ParseBytes([]byte(yamlContent), name)
	require.NoError(t, err, "failed to parse workflow YAML")
	return wf
}

// ---------------------------------------------------------------------------
// VXS-001: pull_request_target with Fork Code Checkout
// ---------------------------------------------------------------------------

func TestVXS001_ForkCheckoutWithHeadSHA(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs001 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-001" {
			vxs001 = append(vxs001, f)
		}
	}

	assert.NotEmpty(t, vxs001, "expected VXS-001 finding for checkout with PR head SHA")
	assert.Equal(t, "critical", vxs001[0].Severity)
	assert.Contains(t, vxs001[0].Evidence, "github.event.pull_request.head.sha")
}

func TestVXS001_ForkCheckoutWithHeadRef(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on:
  pull_request_target:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - run: make test
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs001 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-001" {
			vxs001 = append(vxs001, f)
		}
	}

	assert.NotEmpty(t, vxs001, "expected VXS-001 finding for checkout with github.head_ref")
}

func TestVXS001_SafeCheckout_NoPRTarget(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on:
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs001 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-001" {
			vxs001 = append(vxs001, f)
		}
	}

	assert.Empty(t, vxs001, "should not flag VXS-001 for plain pull_request trigger")
}

func TestVXS001_SafeCheckout_NoForkRef(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/label.yml", `
name: Label
on:
  pull_request_target:
    types: [opened]

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs001 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-001" {
			vxs001 = append(vxs001, f)
		}
	}

	assert.Empty(t, vxs001, "should not flag VXS-001 when pull_request_target does not checkout fork code")
}

// ---------------------------------------------------------------------------
// VXS-002: Expression Injection via Untrusted Input
// ---------------------------------------------------------------------------

func TestVXS002_TaintedPRTitle(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/greet.yml", `
name: Greet
on:
  pull_request:
    types: [opened]

jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - name: Echo PR title
        run: echo "PR title is ${{ github.event.pull_request.title }}"
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs002 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-002" {
			vxs002 = append(vxs002, f)
		}
	}

	assert.NotEmpty(t, vxs002, "expected VXS-002 finding for tainted PR title in run block")
	assert.Contains(t, vxs002[0].Evidence, "github.event.pull_request.title")
}

func TestVXS002_TaintedIssueBody(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/issue.yml", `
name: Issue Handler
on:
  issues:
    types: [opened]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Process issue
        run: |
          BODY="${{ github.event.issue.body }}"
          echo "$BODY"
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs002 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-002" {
			vxs002 = append(vxs002, f)
		}
	}

	assert.NotEmpty(t, vxs002, "expected VXS-002 finding for tainted issue body in run block")
}

func TestVXS002_SafeExpression(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/safe.yml", `
name: Safe
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Show SHA
        run: echo "SHA is ${{ github.sha }}"
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs002 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-002" {
			vxs002 = append(vxs002, f)
		}
	}

	assert.Empty(t, vxs002, "should not flag VXS-002 for github.sha which is not user-controlled")
}

func TestVXS002_TaintedCommentBody(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/comment.yml", `
name: Comment
on:
  issue_comment:
    types: [created]

jobs:
  handle:
    runs-on: ubuntu-latest
    steps:
      - name: Parse comment
        run: echo "${{ github.event.comment.body }}"
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs002 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-002" {
			vxs002 = append(vxs002, f)
		}
	}

	assert.NotEmpty(t, vxs002, "expected VXS-002 for tainted comment body")
}

// ---------------------------------------------------------------------------
// VXS-004: Privileged Trigger with Secrets and No Author Check
// ---------------------------------------------------------------------------

func TestVXS004_IssueCommentWithSecrets(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/deploy.yml", `
name: Deploy on Comment
on:
  issue_comment:
    types: [created]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs004 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-004" {
			vxs004 = append(vxs004, f)
		}
	}

	assert.NotEmpty(t, vxs004, "expected VXS-004 for issue_comment trigger with secrets and no author check")
}

func TestVXS004_WorkflowRunWithSecrets(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/publish.yml", `
name: Publish
on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - name: Publish package
        run: npm publish
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs004 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-004" {
			vxs004 = append(vxs004, f)
		}
	}

	assert.NotEmpty(t, vxs004, "expected VXS-004 for workflow_run with secrets and no author check")
}

func TestVXS004_SafeWithAuthorCheck(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/deploy-safe.yml", `
name: Safe Deploy
on:
  issue_comment:
    types: [created]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Check author
        if: github.event.comment.author_association == 'MEMBER'
        run: echo "Authorized"
      - name: Deploy
        if: github.event.comment.author_association == 'MEMBER'
        run: ./deploy.sh
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs004 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-004" {
			vxs004 = append(vxs004, f)
		}
	}

	assert.Empty(t, vxs004, "should not flag VXS-004 when author_association check is present")
}

func TestVXS004_SafeNonPrivilegedTrigger(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/push.yml", `
name: Push CI
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs004 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-004" {
			vxs004 = append(vxs004, f)
		}
	}

	assert.Empty(t, vxs004, "should not flag VXS-004 for push trigger even with secrets")
}

// ---------------------------------------------------------------------------
// VXS-006: Dangerous Sink in Run Block
// ---------------------------------------------------------------------------

func TestVXS006_EvalWithExpression(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/eval.yml", `
name: Eval Test
on:
  issue_comment:
    types: [created]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Dangerous eval
        run: |
          eval ${{ github.event.comment.body }}
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs006 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-006" {
			vxs006 = append(vxs006, f)
		}
	}

	assert.NotEmpty(t, vxs006, "expected VXS-006 for eval with expression injection")
}

func TestVXS006_CurlPipeBashWithExpression(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/curl.yml", `
name: Curl Pipe Bash Test
on:
  pull_request:
    types: [opened]

jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - name: Install tool
        run: |
          curl -sSfL https://install.example.com/${{ github.event.pull_request.head.ref }}/setup.sh | bash
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs006 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-006" {
			vxs006 = append(vxs006, f)
		}
	}

	assert.NotEmpty(t, vxs006, "expected VXS-006 for curl with expression")
}

func TestVXS006_SafeNoExpression(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/safe-eval.yml", `
name: Safe
on:
  push:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Safe eval
        run: |
          eval "echo hello"
`)

	engine := NewEngineWithDefaults()
	findings := engine.Evaluate([]*parser.Workflow{wf})

	var vxs006 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-006" {
			vxs006 = append(vxs006, f)
		}
	}

	assert.Empty(t, vxs006, "should not flag VXS-006 for eval without expressions")
}

// ---------------------------------------------------------------------------
// Deduplication and Sorting
// ---------------------------------------------------------------------------

func TestDeduplication(t *testing.T) {
	findings := []Finding{
		{RuleID: "VXS-001", File: "a.yml", JobID: "build", LineNumber: 1, Severity: "critical"},
		{RuleID: "VXS-001", File: "a.yml", JobID: "build", LineNumber: 1, Severity: "critical"}, // duplicate
		{RuleID: "VXS-002", File: "a.yml", JobID: "build", LineNumber: 5, Severity: "high"},
	}

	result := deduplicateAndSort(findings)
	assert.Len(t, result, 2, "expected 2 unique findings after deduplication")
}

func TestSortBySeverity(t *testing.T) {
	findings := []Finding{
		{RuleID: "VXS-007", File: "a.yml", Severity: "medium", LineNumber: 10},
		{RuleID: "VXS-001", File: "a.yml", Severity: "critical", LineNumber: 1},
		{RuleID: "VXS-002", File: "a.yml", Severity: "high", LineNumber: 5},
		{RuleID: "VXS-008", File: "a.yml", Severity: "low", LineNumber: 15},
	}

	result := deduplicateAndSort(findings)
	assert.Equal(t, "critical", result[0].Severity)
	assert.Equal(t, "high", result[1].Severity)
	assert.Equal(t, "medium", result[2].Severity)
	assert.Equal(t, "low", result[3].Severity)
}

func TestEvaluateWithDemoContext(t *testing.T) {
	wf := mustParseWorkflow(t, ".github/workflows/ci.yml", `
name: CI
on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`)

	engine := NewEngineWithDefaults()
	demoCtx := map[string]string{
		"VXS-001": "This is a demo context for VXS-001",
	}
	findings := engine.EvaluateWithDemoContext([]*parser.Workflow{wf}, demoCtx)

	var vxs001 []Finding
	for _, f := range findings {
		if f.RuleID == "VXS-001" {
			vxs001 = append(vxs001, f)
		}
	}

	require.NotEmpty(t, vxs001)
	assert.Equal(t, "This is a demo context for VXS-001", vxs001[0].DemoContext)
}
