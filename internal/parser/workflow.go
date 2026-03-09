// Package parser reads GitHub Actions workflow YAML files and converts them
// into typed Go structs that downstream analysis rules can inspect.
package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Workflow is the top-level representation of a single GitHub Actions workflow
// file.  It carries both typed fields for convenience and the raw YAML map so
// that analysis rules can access anything the typed model does not cover.
type Workflow struct {
	Path        string                 // filesystem path of the source file
	Name        string                 // contents of the top-level "name:" key
	Triggers    []string               // raw trigger event names: push, pull_request_target, etc.
	TriggerData map[string]interface{} // full trigger config for deeper inspection
	Jobs        map[string]*Job        // keyed by the YAML job id
	Raw         map[string]interface{} // entire parsed YAML for rule access
	Permissions map[string]string      // workflow-level permissions
}

// Job is a single job definition inside a workflow.
type Job struct {
	ID          string
	Name        string
	RunsOn      string
	Permissions map[string]string // e.g. contents: write, id-token: write
	Steps       []*Step
	Env         map[string]string
	Secrets     []SecretRef
}

// Step is a single step inside a job.
type Step struct {
	ID          string
	Name        string
	Uses        string            // action reference, e.g. actions/checkout@v4
	Run         string            // shell command block
	If          string            // conditional expression
	Env         map[string]string
	With        map[string]string
	Expressions []string          // all ${{ }} expressions extracted from Run, With, Env
	LineNumber  int
}

// SecretRef records one reference to a secret found somewhere in the workflow.
type SecretRef struct {
	Name       string
	Expression string
	LineNumber int
}

// ---------------------------------------------------------------------------
// Package-level compiled regexes (compiled once, not per call).
// ---------------------------------------------------------------------------

// exprRe matches GitHub Actions expression placeholders: ${{ ... }}
var exprRe = regexp.MustCompile(`\$\{\{[^}]+\}\}`)

// secretRe pulls the secret name out of an expression like ${{ secrets.FOO }}.
var secretRe = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]*)`)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ParseFile reads a workflow YAML file from disk and returns a *Workflow.
func ParseFile(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parser: reading %s: %w", path, err)
	}
	return ParseBytes(data, path)
}

// ParseBytes parses workflow YAML from a byte slice.  The path argument is
// stored in the returned Workflow for reference but does not need to point to
// an actual file on disk (useful for embedded demo content).
func ParseBytes(data []byte, path string) (*Workflow, error) {
	// --- 1. Decode into a yaml.Node tree so we can track line numbers. ---
	var docNode yaml.Node
	if err := yaml.Unmarshal(data, &docNode); err != nil {
		return nil, fmt.Errorf("parser: YAML decode of %s: %w", path, err)
	}

	// The top-level node from Unmarshal is a DocumentNode wrapping a MappingNode.
	if docNode.Kind != yaml.DocumentNode || len(docNode.Content) == 0 {
		return nil, fmt.Errorf("parser: %s: unexpected top-level YAML node kind %d", path, docNode.Kind)
	}
	rootNode := docNode.Content[0]
	if rootNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parser: %s: top-level YAML element is not a mapping", path)
	}

	// --- 2. Decode into a plain map[string]interface{} for easy value access. ---
	raw, err := decodeToStringKeyMap(data)
	if err != nil {
		return nil, fmt.Errorf("parser: YAML decode of %s (raw): %w", path, err)
	}

	// Handle the YAML "on" key quirk: YAML 1.1 parsers interpret bare `on` as
	// boolean true, so the map may have a key "true" instead of "on".
	normalizeOnKey(raw)

	wf := &Workflow{
		Path:        path,
		Raw:         raw,
		Jobs:        make(map[string]*Job),
		TriggerData: make(map[string]interface{}),
		Permissions: make(map[string]string),
	}

	// --- 3. Name ---
	if v, ok := raw["name"]; ok {
		wf.Name = toString(v)
	}

	// --- 4. Triggers ---
	parseTriggers(raw, wf)

	// --- 5. Workflow-level permissions ---
	if p, ok := raw["permissions"]; ok {
		wf.Permissions = parsePermissions(p)
	}

	// --- 6. Build a line-number index from the Node tree. ---
	stepLines := buildStepLineIndex(rootNode)

	// --- 7. Jobs ---
	jobsRaw, _ := raw["jobs"]
	if jobsMap, ok := jobsRaw.(map[string]interface{}); ok {
		for jobID, jobVal := range jobsMap {
			jm, ok := jobVal.(map[string]interface{})
			if !ok {
				continue
			}
			job := parseJob(jobID, jm, stepLines)
			wf.Jobs[jobID] = job
		}
	}

	return wf, nil
}

// dangerousPaths lists directories that should never be scanned recursively
// to prevent accidental full-filesystem walks.
var dangerousPaths = map[string]bool{
	"/":     true,
	"/home": true,
	"/usr":  true,
	"/var":  true,
	"/etc":  true,
	"/tmp":  true,
}

// ParseDirectory recursively finds all .yml and .yaml files under
// <dir>/.github/workflows/ and parses each one.  It returns all successfully
// parsed workflows; if any file fails to parse the error is returned
// immediately.
func ParseDirectory(dir string) ([]*Workflow, error) {
	// Resolve to absolute path for safety check.
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("parser: resolve path %s: %w", dir, err)
	}

	// Block scanning dangerous root-level directories.
	if dangerousPaths[absDir] {
		return nil, fmt.Errorf("refusing to scan %s -- this would recursively walk a system directory. "+
			"Point runner-guard at a specific repository or .github/workflows/ directory instead", absDir)
	}

	// Warn if scanning a home directory (contains many non-workflow files).
	home, _ := os.UserHomeDir()
	if home != "" && absDir == home {
		return nil, fmt.Errorf("refusing to scan home directory %s -- this would recursively walk all your files. "+
			"Point runner-guard at a specific repository or .github/workflows/ directory instead", absDir)
	}

	// First try the standard GitHub Actions path.
	workflowDir := filepath.Join(dir, ".github", "workflows")
	if info, err := os.Stat(workflowDir); err == nil && info.IsDir() {
		return scanDir(workflowDir)
	}

	// Fall back: scan the provided directory recursively for .yml/.yaml files.
	// This supports scanning directories like demo/vulnerable/ directly.
	return scanDir(dir)
}

// scanDir walks a directory tree and parses all .yml/.yaml files found.
func scanDir(dir string) ([]*Workflow, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("parser: stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("parser: %s is not a directory", dir)
	}

	var workflows []*Workflow
	walkErr := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		wf, parseErr := ParseFile(p)
		if parseErr != nil {
			// Warn but continue scanning other files.
			fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", p, parseErr)
			return nil
		}
		workflows = append(workflows, wf)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return workflows, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// decodeToStringKeyMap unmarshals YAML bytes and ensures all map keys are
// strings.  gopkg.in/yaml.v3 may produce map[string]interface{} directly
// when decoding into interface{}, but we normalise defensively.
func decodeToStringKeyMap(data []byte) (map[string]interface{}, error) {
	var raw interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	normalised := normalizeValue(raw)
	m, ok := normalised.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("top-level YAML value is not a mapping")
	}
	return m, nil
}

// normalizeValue recursively converts every map in the tree to use string
// keys.  gopkg.in/yaml.v3 usually returns map[string]interface{} when
// decoding into interface{}, but the "on" -> true boolean key is an
// exception, and older YAML libraries return map[interface{}]interface{}.
func normalizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			out[fmt.Sprintf("%v", k)] = normalizeValue(vv)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			out[k] = normalizeValue(vv)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, vv := range val {
			out[i] = normalizeValue(vv)
		}
		return out
	default:
		return v
	}
}

// normalizeOnKey handles the YAML 1.1 quirk where the bare key `on` is
// decoded as the boolean true.  After normalizeValue the boolean key becomes
// the string "true".
func normalizeOnKey(raw map[string]interface{}) {
	if _, hasOn := raw["on"]; hasOn {
		return // already correct
	}
	if v, ok := raw["true"]; ok {
		raw["on"] = v
		delete(raw, "true")
	}
}

// parseTriggers extracts trigger event names and their configurations from
// the "on" key.  GitHub Actions accepts three forms:
//
//	on: push                          # single string
//	on: [push, pull_request]          # list of strings
//	on:                               # mapping with per-event config
//	  push:
//	    branches: [main]
func parseTriggers(raw map[string]interface{}, wf *Workflow) {
	onVal, ok := raw["on"]
	if !ok {
		return
	}

	switch v := onVal.(type) {
	case string:
		wf.Triggers = append(wf.Triggers, v)
		wf.TriggerData[v] = nil

	case []interface{}:
		for _, item := range v {
			name := toString(item)
			if name != "" {
				wf.Triggers = append(wf.Triggers, name)
				wf.TriggerData[name] = nil
			}
		}

	case map[string]interface{}:
		for eventName, eventCfg := range v {
			wf.Triggers = append(wf.Triggers, eventName)
			wf.TriggerData[eventName] = eventCfg
		}
	}
}

// parsePermissions converts the YAML permissions block into a map.
// Permissions can be either a string (e.g. "read-all") or a map of
// individual scopes.
func parsePermissions(val interface{}) map[string]string {
	perms := make(map[string]string)
	switch v := val.(type) {
	case string:
		perms["_all"] = v
	case map[string]interface{}:
		for k, pv := range v {
			perms[k] = toString(pv)
		}
	}
	return perms
}

// parseJob constructs a *Job from the raw YAML map for that job.
func parseJob(id string, m map[string]interface{}, stepLines map[string]map[int]int) *Job {
	job := &Job{
		ID:          id,
		Env:         make(map[string]string),
		Permissions: make(map[string]string),
	}

	if v, ok := m["name"]; ok {
		job.Name = toString(v)
	}

	if v, ok := m["runs-on"]; ok {
		job.RunsOn = toString(v)
	}

	if v, ok := m["permissions"]; ok {
		job.Permissions = parsePermissions(v)
	}

	if v, ok := m["env"]; ok {
		job.Env = toStringMap(v)
	}

	// Steps
	if stepsRaw, ok := m["steps"]; ok {
		if stepsList, ok := stepsRaw.([]interface{}); ok {
			for i, stepRaw := range stepsList {
				sm, ok := stepRaw.(map[string]interface{})
				if !ok {
					continue
				}
				step := parseStep(sm)

				// Attach line number from the Node index if available.
				if jobLines, ok := stepLines[id]; ok {
					if ln, ok := jobLines[i]; ok {
						step.LineNumber = ln
					}
				}

				// Collect secret references from all expressions in this step.
				for _, expr := range step.Expressions {
					for _, match := range secretRe.FindAllStringSubmatch(expr, -1) {
						job.Secrets = append(job.Secrets, SecretRef{
							Name:       match[1],
							Expression: expr,
							LineNumber: step.LineNumber,
						})
					}
				}

				job.Steps = append(job.Steps, step)
			}
		}
	}

	return job
}

// parseStep constructs a *Step from the raw YAML map for that step.
func parseStep(m map[string]interface{}) *Step {
	step := &Step{
		Env:  make(map[string]string),
		With: make(map[string]string),
	}

	if v, ok := m["id"]; ok {
		step.ID = toString(v)
	}
	if v, ok := m["name"]; ok {
		step.Name = toString(v)
	}
	if v, ok := m["uses"]; ok {
		step.Uses = toString(v)
	}
	if v, ok := m["run"]; ok {
		step.Run = toString(v)
	}
	if v, ok := m["if"]; ok {
		step.If = toString(v)
	}
	if v, ok := m["env"]; ok {
		step.Env = toStringMap(v)
	}
	if v, ok := m["with"]; ok {
		step.With = toStringMap(v)
	}

	// Extract all ${{ }} expressions from every string-valued field.
	step.Expressions = extractExpressions(step)

	return step
}

// extractExpressions scans Run, With, Env, If, Name, and Uses for ${{ }}
// expression placeholders and returns them all de-duplicated.
func extractExpressions(step *Step) []string {
	seen := make(map[string]struct{})
	var exprs []string

	collect := func(s string) {
		for _, m := range exprRe.FindAllString(s, -1) {
			if _, dup := seen[m]; !dup {
				seen[m] = struct{}{}
				exprs = append(exprs, m)
			}
		}
	}

	collect(step.Run)
	collect(step.If)
	collect(step.Name)
	collect(step.Uses)
	for _, v := range step.Env {
		collect(v)
	}
	for _, v := range step.With {
		collect(v)
	}

	return exprs
}

// buildStepLineIndex walks the yaml.Node tree and returns a nested map:
//
//	jobID -> stepIndex -> lineNumber
//
// This lets us annotate each Step with its source line.
func buildStepLineIndex(root *yaml.Node) map[string]map[int]int {
	result := make(map[string]map[int]int)

	// root is a MappingNode.  Find the "jobs" key.
	jobsNode := mappingLookup(root, "jobs")
	if jobsNode == nil || jobsNode.Kind != yaml.MappingNode {
		return result
	}

	// Iterate over job entries.
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		keyNode := jobsNode.Content[i]
		valNode := jobsNode.Content[i+1]

		jobID := keyNode.Value
		if valNode.Kind != yaml.MappingNode {
			continue
		}

		stepsNode := mappingLookup(valNode, "steps")
		if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
			continue
		}

		lineMap := make(map[int]int, len(stepsNode.Content))
		for idx, stepNode := range stepsNode.Content {
			lineMap[idx] = stepNode.Line
		}
		result[jobID] = lineMap
	}

	return result
}

// mappingLookup finds a value node inside a MappingNode by key name.
func mappingLookup(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i]
		if k.Value == key {
			return node.Content[i+1]
		}
		// Special case: YAML may decode "on" as boolean true (tag !!bool,
		// value "true").
		if key == "on" && k.Tag == "!!bool" && k.Value == "true" {
			return node.Content[i+1]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

// toString coerces an interface{} to string in a best-effort manner.
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case bool:
		if val {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case float64:
		return fmt.Sprintf("%g", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// toStringMap converts an interface{} that is expected to be a
// map[string]interface{} into a map[string]string.
func toStringMap(v interface{}) map[string]string {
	out := make(map[string]string)
	if m, ok := v.(map[string]interface{}); ok {
		for k, val := range m {
			out[k] = toString(val)
		}
	}
	return out
}
