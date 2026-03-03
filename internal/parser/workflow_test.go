package parser

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: basic workflow with pull_request_target trigger
// ---------------------------------------------------------------------------

func TestParseBytes_PullRequestTarget(t *testing.T) {
	yaml := []byte(`
name: PR Handler
on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Greet
        run: echo "Hello ${{ github.event.pull_request.head.ref }}"
`)

	wf, err := ParseBytes(yaml, "test.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	if wf.Name != "PR Handler" {
		t.Errorf("Name = %q, want %q", wf.Name, "PR Handler")
	}

	if len(wf.Triggers) != 1 || wf.Triggers[0] != "pull_request_target" {
		t.Errorf("Triggers = %v, want [pull_request_target]", wf.Triggers)
	}

	if wf.TriggerData["pull_request_target"] == nil {
		t.Error("TriggerData[pull_request_target] should not be nil (has types config)")
	}

	if wf.Permissions["contents"] != "read" {
		t.Errorf("Permissions[contents] = %q, want %q", wf.Permissions["contents"], "read")
	}
	if wf.Permissions["pull-requests"] != "write" {
		t.Errorf("Permissions[pull-requests] = %q, want %q", wf.Permissions["pull-requests"], "write")
	}

	job, ok := wf.Jobs["check"]
	if !ok {
		t.Fatal("expected job 'check'")
	}
	if job.RunsOn != "ubuntu-latest" {
		t.Errorf("RunsOn = %q, want %q", job.RunsOn, "ubuntu-latest")
	}
	if len(job.Steps) != 2 {
		t.Fatalf("len(Steps) = %d, want 2", len(job.Steps))
	}

	// First step: actions/checkout
	s0 := job.Steps[0]
	if s0.Uses != "actions/checkout@v4" {
		t.Errorf("Steps[0].Uses = %q, want %q", s0.Uses, "actions/checkout@v4")
	}
	if s0.With["ref"] != "${{ github.event.pull_request.head.sha }}" {
		t.Errorf("Steps[0].With[ref] = %q", s0.With["ref"])
	}

	// Second step: run with expression
	s1 := job.Steps[1]
	if s1.Name != "Greet" {
		t.Errorf("Steps[1].Name = %q, want %q", s1.Name, "Greet")
	}
	if len(s1.Expressions) == 0 {
		t.Fatal("expected expressions in step 1")
	}
}

// ---------------------------------------------------------------------------
// Test: expression extraction from run blocks
// ---------------------------------------------------------------------------

func TestParseBytes_ExpressionExtraction(t *testing.T) {
	yaml := []byte(`
name: Expressions
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Multi-expr
        run: |
          echo "${{ github.event.issue.title }}"
          curl "${{ github.event.issue.body }}"
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
`)

	wf, err := ParseBytes(yaml, "expr.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	job := wf.Jobs["build"]
	if job == nil {
		t.Fatal("expected job 'build'")
	}

	step := job.Steps[0]
	// Should find at least 3 expressions: issue.title, issue.body, secrets.GITHUB_TOKEN
	if len(step.Expressions) < 3 {
		t.Errorf("len(Expressions) = %d, want >= 3; got %v", len(step.Expressions), step.Expressions)
	}

	found := make(map[string]bool)
	for _, e := range step.Expressions {
		found[e] = true
	}
	for _, want := range []string{
		"${{ github.event.issue.title }}",
		"${{ github.event.issue.body }}",
		"${{ secrets.GITHUB_TOKEN }}",
	} {
		if !found[want] {
			t.Errorf("missing expected expression %q in %v", want, step.Expressions)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: permissions at both workflow and job level
// ---------------------------------------------------------------------------

func TestParseBytes_PermissionsWorkflowAndJob(t *testing.T) {
	yaml := []byte(`
name: Perm Test
on: push
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - run: echo deploy
`)

	wf, err := ParseBytes(yaml, "perm.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	// Workflow-level
	if wf.Permissions["contents"] != "read" {
		t.Errorf("workflow Permissions[contents] = %q, want %q", wf.Permissions["contents"], "read")
	}

	// Job-level
	job := wf.Jobs["deploy"]
	if job == nil {
		t.Fatal("expected job 'deploy'")
	}
	if job.Permissions["contents"] != "write" {
		t.Errorf("job Permissions[contents] = %q, want %q", job.Permissions["contents"], "write")
	}
	if job.Permissions["id-token"] != "write" {
		t.Errorf("job Permissions[id-token] = %q, want %q", job.Permissions["id-token"], "write")
	}
}

// ---------------------------------------------------------------------------
// Test: string-level "read-all" permissions
// ---------------------------------------------------------------------------

func TestParseBytes_PermissionsString(t *testing.T) {
	yaml := []byte(`
name: ReadAll
on: push
permissions: read-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`)

	wf, err := ParseBytes(yaml, "permstr.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}
	if wf.Permissions["_all"] != "read-all" {
		t.Errorf("Permissions[_all] = %q, want %q", wf.Permissions["_all"], "read-all")
	}
}

// ---------------------------------------------------------------------------
// Test: secret reference extraction
// ---------------------------------------------------------------------------

func TestParseBytes_SecretExtraction(t *testing.T) {
	yaml := []byte(`
name: Secrets
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - name: Publish
        run: npm publish
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
`)

	wf, err := ParseBytes(yaml, "secrets.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	job := wf.Jobs["release"]
	if job == nil {
		t.Fatal("expected job 'release'")
	}
	if len(job.Secrets) < 2 {
		t.Fatalf("len(Secrets) = %d, want >= 2", len(job.Secrets))
	}

	names := make(map[string]bool)
	for _, s := range job.Secrets {
		names[s.Name] = true
	}
	if !names["NPM_TOKEN"] {
		t.Error("missing secret NPM_TOKEN")
	}
	if !names["DEPLOY_KEY"] {
		t.Error("missing secret DEPLOY_KEY")
	}
}

// ---------------------------------------------------------------------------
// Test: on as a list of strings
// ---------------------------------------------------------------------------

func TestParseBytes_OnAsList(t *testing.T) {
	yaml := []byte(`
name: List Triggers
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`)

	wf, err := ParseBytes(yaml, "list.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	sort.Strings(wf.Triggers)
	if len(wf.Triggers) != 2 {
		t.Fatalf("len(Triggers) = %d, want 2", len(wf.Triggers))
	}
	if wf.Triggers[0] != "pull_request" || wf.Triggers[1] != "push" {
		t.Errorf("Triggers = %v, want [pull_request, push]", wf.Triggers)
	}
}

// ---------------------------------------------------------------------------
// Test: on as a single string
// ---------------------------------------------------------------------------

func TestParseBytes_OnAsSingleString(t *testing.T) {
	yaml := []byte(`
name: Single Trigger
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
`)

	wf, err := ParseBytes(yaml, "single.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	if len(wf.Triggers) != 1 || wf.Triggers[0] != "push" {
		t.Errorf("Triggers = %v, want [push]", wf.Triggers)
	}
}

// ---------------------------------------------------------------------------
// Test: workflow with no jobs
// ---------------------------------------------------------------------------

func TestParseBytes_NoJobs(t *testing.T) {
	yaml := []byte(`
name: Empty
on: push
`)

	wf, err := ParseBytes(yaml, "empty.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	if len(wf.Jobs) != 0 {
		t.Errorf("len(Jobs) = %d, want 0", len(wf.Jobs))
	}
	if wf.Name != "Empty" {
		t.Errorf("Name = %q, want %q", wf.Name, "Empty")
	}
}

// ---------------------------------------------------------------------------
// Test: multiple jobs with different configurations
// ---------------------------------------------------------------------------

func TestParseBytes_MultipleJobs(t *testing.T) {
	yaml := []byte(`
name: Multi
on: push
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run lint
  test:
    runs-on: ubuntu-22.04
    env:
      CI: "true"
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: npm test
        env:
          NODE_ENV: test
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - name: Deploy
        run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`)

	wf, err := ParseBytes(yaml, "multi.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	if len(wf.Jobs) != 3 {
		t.Fatalf("len(Jobs) = %d, want 3", len(wf.Jobs))
	}

	// lint job
	lint := wf.Jobs["lint"]
	if lint == nil {
		t.Fatal("expected job 'lint'")
	}
	if lint.RunsOn != "ubuntu-latest" {
		t.Errorf("lint.RunsOn = %q", lint.RunsOn)
	}
	if len(lint.Steps) != 2 {
		t.Errorf("len(lint.Steps) = %d, want 2", len(lint.Steps))
	}

	// test job
	testJob := wf.Jobs["test"]
	if testJob == nil {
		t.Fatal("expected job 'test'")
	}
	if testJob.RunsOn != "ubuntu-22.04" {
		t.Errorf("test.RunsOn = %q", testJob.RunsOn)
	}
	if testJob.Env["CI"] != "true" {
		t.Errorf("test.Env[CI] = %q, want %q", testJob.Env["CI"], "true")
	}
	if len(testJob.Steps) != 2 {
		t.Errorf("len(test.Steps) = %d, want 2", len(testJob.Steps))
	}
	if testJob.Steps[1].Env["NODE_ENV"] != "test" {
		t.Errorf("test step env NODE_ENV = %q", testJob.Steps[1].Env["NODE_ENV"])
	}

	// deploy job
	deploy := wf.Jobs["deploy"]
	if deploy == nil {
		t.Fatal("expected job 'deploy'")
	}
	if deploy.Permissions["contents"] != "write" {
		t.Errorf("deploy.Permissions[contents] = %q", deploy.Permissions["contents"])
	}
	if len(deploy.Secrets) != 1 {
		t.Fatalf("len(deploy.Secrets) = %d, want 1", len(deploy.Secrets))
	}
	if deploy.Secrets[0].Name != "DEPLOY_TOKEN" {
		t.Errorf("deploy.Secrets[0].Name = %q, want %q", deploy.Secrets[0].Name, "DEPLOY_TOKEN")
	}
}

// ---------------------------------------------------------------------------
// Test: line numbers are tracked
// ---------------------------------------------------------------------------

func TestParseBytes_LineNumbers(t *testing.T) {
	yaml := []byte(`name: Lines
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo first
      - run: echo second
      - run: echo third
`)

	wf, err := ParseBytes(yaml, "lines.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	job := wf.Jobs["build"]
	if job == nil {
		t.Fatal("expected job 'build'")
	}
	if len(job.Steps) != 3 {
		t.Fatalf("len(Steps) = %d, want 3", len(job.Steps))
	}

	// Line numbers should be positive and ascending.
	for i, s := range job.Steps {
		if s.LineNumber <= 0 {
			t.Errorf("Steps[%d].LineNumber = %d, want > 0", i, s.LineNumber)
		}
		if i > 0 && s.LineNumber <= job.Steps[i-1].LineNumber {
			t.Errorf("Steps[%d].LineNumber (%d) should be > Steps[%d].LineNumber (%d)",
				i, s.LineNumber, i-1, job.Steps[i-1].LineNumber)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: on as a map trigger config
// ---------------------------------------------------------------------------

func TestParseBytes_OnAsMap(t *testing.T) {
	yaml := []byte(`
name: Map Triggers
on:
  push:
    branches: [main]
  pull_request:
    types: [opened]
jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - run: echo ci
`)

	wf, err := ParseBytes(yaml, "map.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	if len(wf.Triggers) != 2 {
		t.Fatalf("len(Triggers) = %d, want 2", len(wf.Triggers))
	}

	sort.Strings(wf.Triggers)
	if wf.Triggers[0] != "pull_request" || wf.Triggers[1] != "push" {
		t.Errorf("Triggers = %v, want [pull_request, push]", wf.Triggers)
	}

	// push should have branch config
	if wf.TriggerData["push"] == nil {
		t.Error("TriggerData[push] should not be nil")
	}
}

// ---------------------------------------------------------------------------
// Test: if conditional on steps
// ---------------------------------------------------------------------------

func TestParseBytes_StepIfCondition(t *testing.T) {
	yaml := []byte(`
name: Conditional
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Only main
        if: github.ref == 'refs/heads/main'
        run: echo "on main"
      - name: PR only
        if: ${{ github.event_name == 'pull_request' }}
        run: echo "pr"
`)

	wf, err := ParseBytes(yaml, "cond.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	job := wf.Jobs["build"]
	if job == nil {
		t.Fatal("expected job 'build'")
	}
	if len(job.Steps) != 2 {
		t.Fatalf("len(Steps) = %d, want 2", len(job.Steps))
	}

	if job.Steps[0].If != "github.ref == 'refs/heads/main'" {
		t.Errorf("Steps[0].If = %q", job.Steps[0].If)
	}

	// The second step has ${{ }} in if, which should be extracted.
	found := false
	for _, e := range job.Steps[1].Expressions {
		if e == "${{ github.event_name == 'pull_request' }}" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected expression in step 1; got %v", job.Steps[1].Expressions)
	}
}

// ---------------------------------------------------------------------------
// Test: step ID extraction
// ---------------------------------------------------------------------------

func TestParseBytes_StepID(t *testing.T) {
	yaml := []byte(`
name: StepID
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: setup
        run: echo setup
      - id: build
        run: echo build
`)

	wf, err := ParseBytes(yaml, "id.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	job := wf.Jobs["build"]
	if job == nil {
		t.Fatal("expected job 'build'")
	}
	if job.Steps[0].ID != "setup" {
		t.Errorf("Steps[0].ID = %q, want %q", job.Steps[0].ID, "setup")
	}
	if job.Steps[1].ID != "build" {
		t.Errorf("Steps[1].ID = %q, want %q", job.Steps[1].ID, "build")
	}
}

// ---------------------------------------------------------------------------
// Test: Raw field is populated
// ---------------------------------------------------------------------------

func TestParseBytes_RawField(t *testing.T) {
	yaml := []byte(`
name: Raw
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo raw
`)

	wf, err := ParseBytes(yaml, "raw.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	if wf.Raw == nil {
		t.Fatal("Raw should not be nil")
	}
	if wf.Raw["name"] != "Raw" {
		t.Errorf("Raw[name] = %v, want %q", wf.Raw["name"], "Raw")
	}
}

// ---------------------------------------------------------------------------
// Test: duplicate expression de-duplication
// ---------------------------------------------------------------------------

func TestParseBytes_DuplicateExpressions(t *testing.T) {
	yaml := []byte(`
name: Dupes
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo ${{ github.sha }}
          echo ${{ github.sha }}
          echo ${{ github.ref }}
`)

	wf, err := ParseBytes(yaml, "dupes.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	step := wf.Jobs["build"].Steps[0]
	// ${{ github.sha }} should appear only once despite being used twice.
	count := 0
	for _, e := range step.Expressions {
		if e == "${{ github.sha }}" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("${{ github.sha }} appears %d times, want 1 (de-duplication)", count)
	}
	if len(step.Expressions) != 2 {
		t.Errorf("len(Expressions) = %d, want 2; got %v", len(step.Expressions), step.Expressions)
	}
}

// ---------------------------------------------------------------------------
// Test: ParseFile with a real temp file
// ---------------------------------------------------------------------------

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yml")
	content := []byte(`
name: File Test
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	wf, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if wf.Name != "File Test" {
		t.Errorf("Name = %q, want %q", wf.Name, "File Test")
	}
	if wf.Path != path {
		t.Errorf("Path = %q, want %q", wf.Path, path)
	}
}

// ---------------------------------------------------------------------------
// Test: ParseFile with missing file
// ---------------------------------------------------------------------------

func TestParseFile_NotFound(t *testing.T) {
	_, err := ParseFile("/nonexistent/path/to/workflow.yml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// Test: ParseDirectory
// ---------------------------------------------------------------------------

func TestParseDirectory(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create two workflow files.
	for _, name := range []string{"ci.yml", "deploy.yaml"} {
		content := []byte(`
name: ` + name + `
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ` + name + `
`)
		if err := os.WriteFile(filepath.Join(wfDir, name), content, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Also create a non-YAML file that should be ignored.
	if err := os.WriteFile(filepath.Join(wfDir, "readme.txt"), []byte("ignore me"), 0644); err != nil {
		t.Fatal(err)
	}

	wfs, err := ParseDirectory(dir)
	if err != nil {
		t.Fatalf("ParseDirectory failed: %v", err)
	}
	if len(wfs) != 2 {
		t.Errorf("len(workflows) = %d, want 2", len(wfs))
	}
}

// ---------------------------------------------------------------------------
// Test: ParseDirectory with no .github/workflows
// ---------------------------------------------------------------------------

func TestParseDirectory_NoWorkflowsDir(t *testing.T) {
	dir := t.TempDir()
	wfs, err := ParseDirectory(dir)
	if err != nil {
		t.Fatalf("ParseDirectory failed: %v", err)
	}
	if len(wfs) != 0 {
		t.Errorf("len(workflows) = %d, want 0", len(wfs))
	}
}

// ---------------------------------------------------------------------------
// Test: complex real-world-ish workflow
// ---------------------------------------------------------------------------

func TestParseBytes_ComplexWorkflow(t *testing.T) {
	yaml := []byte(`
name: CI Pipeline
on:
  pull_request_target:
    types: [opened, synchronize, reopened]
  issue_comment:
    types: [created]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Check title
        run: |
          TITLE="${{ github.event.pull_request.title }}"
          if [[ ! "$TITLE" =~ ^(feat|fix|chore) ]]; then
            echo "Bad title"
            exit 1
          fi
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    env:
      ENVIRONMENT: production
    steps:
      - uses: actions/checkout@v4
      - name: Deploy
        run: ./scripts/deploy.sh
        env:
          AWS_KEY: ${{ secrets.AWS_ACCESS_KEY }}
          AWS_SECRET: ${{ secrets.AWS_SECRET_KEY }}
          COMMIT: ${{ github.sha }}
`)

	wf, err := ParseBytes(yaml, "complex.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	// Triggers
	if len(wf.Triggers) != 2 {
		t.Fatalf("len(Triggers) = %d, want 2", len(wf.Triggers))
	}

	triggerSet := make(map[string]bool)
	for _, tr := range wf.Triggers {
		triggerSet[tr] = true
	}
	if !triggerSet["pull_request_target"] {
		t.Error("missing trigger pull_request_target")
	}
	if !triggerSet["issue_comment"] {
		t.Error("missing trigger issue_comment")
	}

	// Workflow permissions
	if wf.Permissions["contents"] != "read" {
		t.Errorf("wf perm contents = %q", wf.Permissions["contents"])
	}

	// Validate job
	validate := wf.Jobs["validate"]
	if validate == nil {
		t.Fatal("expected job 'validate'")
	}
	if validate.Permissions["contents"] != "read" {
		t.Errorf("validate perm contents = %q", validate.Permissions["contents"])
	}
	if len(validate.Steps) != 2 {
		t.Fatalf("validate steps = %d", len(validate.Steps))
	}

	// Check the run step extracts title expression and secret
	runStep := validate.Steps[1]
	exprSet := make(map[string]bool)
	for _, e := range runStep.Expressions {
		exprSet[e] = true
	}
	if !exprSet["${{ github.event.pull_request.title }}"] {
		t.Errorf("missing title expression; got %v", runStep.Expressions)
	}
	if !exprSet["${{ secrets.GITHUB_TOKEN }}"] {
		t.Errorf("missing GITHUB_TOKEN expression; got %v", runStep.Expressions)
	}

	// Validate job should have GITHUB_TOKEN secret ref
	secretNames := make(map[string]bool)
	for _, s := range validate.Secrets {
		secretNames[s.Name] = true
	}
	if !secretNames["GITHUB_TOKEN"] {
		t.Error("missing secret ref GITHUB_TOKEN in validate job")
	}

	// Deploy job
	deploy := wf.Jobs["deploy"]
	if deploy == nil {
		t.Fatal("expected job 'deploy'")
	}
	if deploy.Permissions["id-token"] != "write" {
		t.Errorf("deploy perm id-token = %q", deploy.Permissions["id-token"])
	}
	if deploy.Env["ENVIRONMENT"] != "production" {
		t.Errorf("deploy env ENVIRONMENT = %q", deploy.Env["ENVIRONMENT"])
	}

	// Deploy secrets
	deploySecretNames := make(map[string]bool)
	for _, s := range deploy.Secrets {
		deploySecretNames[s.Name] = true
	}
	if !deploySecretNames["AWS_ACCESS_KEY"] {
		t.Error("missing secret ref AWS_ACCESS_KEY")
	}
	if !deploySecretNames["AWS_SECRET_KEY"] {
		t.Error("missing secret ref AWS_SECRET_KEY")
	}
}

// ---------------------------------------------------------------------------
// Test: invalid YAML returns error
// ---------------------------------------------------------------------------

func TestParseBytes_InvalidYAML(t *testing.T) {
	data := []byte(`
name: Bad
on: push
jobs:
  a:
    - this is not valid mapping
  [broken
`)
	_, err := ParseBytes(data, "bad.yml")
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// ---------------------------------------------------------------------------
// Test: with values containing expressions
// ---------------------------------------------------------------------------

func TestParseBytes_WithExpressions(t *testing.T) {
	yaml := []byte(`
name: With
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.PAT }}
          script: |
            console.log("${{ github.actor }}")
`)

	wf, err := ParseBytes(yaml, "with.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}

	step := wf.Jobs["build"].Steps[0]
	exprSet := make(map[string]bool)
	for _, e := range step.Expressions {
		exprSet[e] = true
	}
	if !exprSet["${{ secrets.PAT }}"] {
		t.Errorf("missing ${{ secrets.PAT }} in expressions; got %v", step.Expressions)
	}
	if !exprSet["${{ github.actor }}"] {
		t.Errorf("missing ${{ github.actor }} in expressions; got %v", step.Expressions)
	}
}
