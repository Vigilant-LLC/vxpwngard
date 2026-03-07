package tracking

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// scanResultJSON matches the JSON output format from vxpwngard scan --format json.
type scanResultJSON struct {
	Findings []scanFindingJSON `json:"findings"`
	Summary  struct {
		Total    int `json:"total"`
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
	} `json:"summary"`
}

type scanFindingJSON struct {
	RuleID       string `json:"RuleID"`
	Severity     string `json:"Severity"`
	File         string `json:"File"`
	LineNumber   int    `json:"LineNumber"`
}

// ImportTargetsTSV reads a scan-targets.tsv file and inserts repos into the DB.
// Returns the number of repos imported.
func (d *DB) ImportTargetsTSV(tsvPath string) (int, error) {
	f, err := os.Open(tsvPath)
	if err != nil {
		return 0, fmt.Errorf("opening targets file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	imported := 0

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 2 {
			continue
		}

		repo := parts[0]
		stars := 0
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &stars)
		}
		language := ""
		if len(parts) >= 3 {
			language = parts[2]
		}

		repoParts := strings.SplitN(repo, "/", 2)
		if len(repoParts) != 2 {
			continue
		}

		if _, err := d.UpsertRepo(repoParts[0], repoParts[1], stars, language); err != nil {
			return imported, fmt.Errorf("importing repo %s: %w", repo, err)
		}
		imported++
	}

	return imported, scanner.Err()
}

// ImportScanResults reads JSON scan result files from a directory and inserts
// findings into the DB. Files must be named "owner__repo.json" (double
// underscore separating owner and repo name).
func (d *DB) ImportScanResults(resultsDir string) (int, error) {
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		return 0, fmt.Errorf("reading results directory: %w", err)
	}

	imported := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".json" {
			continue
		}

		// Parse repo name from filename: "owner__repo.json" → "owner/repo"
		baseName := strings.TrimSuffix(entry.Name(), ext)
		repoParts := strings.SplitN(baseName, "__", 2)
		if len(repoParts) != 2 {
			continue
		}
		fullName := repoParts[0] + "/" + repoParts[1]

		// Read and parse the JSON file.
		data, err := os.ReadFile(filepath.Join(resultsDir, entry.Name()))
		if err != nil {
			continue // skip unreadable files
		}

		var result scanResultJSON
		if err := json.Unmarshal(data, &result); err != nil {
			continue // skip unparseable files
		}

		// Ensure repo exists in DB.
		repo, err := d.GetRepoByFullName(fullName)
		if err != nil {
			continue
		}

		var repoID int64
		if repo != nil {
			repoID = repo.ID
		} else {
			// Create repo with no star/language data (we'll get that from TSV import).
			repoID, err = d.UpsertRepo(repoParts[0], repoParts[1], 0, "")
			if err != nil {
				continue
			}
		}

		// Check if this repo already has a completed scan (avoid duplicates).
		var existingScan int
		d.db.QueryRow(`
			SELECT COUNT(*) FROM scans WHERE repo_id = ? AND status = 'completed'
		`, repoID).Scan(&existingScan)
		if existingScan > 0 {
			continue
		}

		// Determine scan status.
		status := StatusCompleted
		if result.Summary.Total == 0 {
			// Could be no_workflows or clean — we mark completed either way.
			status = StatusCompleted
		}

		scanID, err := d.InsertScan(repoID, status, 0, "")
		if err != nil {
			continue
		}

		// Insert findings.
		for _, f := range result.Findings {
			d.InsertFinding(scanID, f.RuleID, f.Severity, f.File, f.LineNumber)
		}

		imported++
	}

	return imported, nil
}
