package rules

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuleMetadata holds the parsed content of a rule YAML definition file.
type RuleMetadata struct {
	ID                string   `yaml:"id"`
	Name              string   `yaml:"name"`
	Severity          string   `yaml:"severity"`
	Description       string   `yaml:"description"`
	Tags              []string `yaml:"tags"`
	AttackScenario    string   `yaml:"attack_scenario"`
	RealWorldIncident string   `yaml:"real_world_incident"`
	Fix               string   `yaml:"fix"`
	References        []string `yaml:"references"`
}

// LoadRules reads all .yaml files from the provided filesystem, parses them into
// RuleMetadata structs, and returns a map keyed by rule ID.
// The fs.FS should contain YAML files at its root or in subdirectories.
func LoadRules(fsys fs.FS) (map[string]*RuleMetadata, error) {
	rules := make(map[string]*RuleMetadata)

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading rule file %s: %w", path, err)
		}

		var meta RuleMetadata
		if err := yaml.Unmarshal(data, &meta); err != nil {
			return fmt.Errorf("parsing rule file %s: %w", path, err)
		}

		if meta.ID == "" {
			return fmt.Errorf("rule file %s has no 'id' field", path)
		}

		if _, exists := rules[meta.ID]; exists {
			return fmt.Errorf("duplicate rule ID %s found in %s", meta.ID, path)
		}

		rules[meta.ID] = &meta
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("loading rules: %w", err)
	}

	return rules, nil
}
