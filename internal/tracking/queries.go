package tracking

import (
	"database/sql"
	"fmt"

	"github.com/Vigilant-LLC/vxpwngard/internal/autofix"
)

// fixableRules lists rule IDs that have auto-fix support.
var fixableRules map[string]bool

func init() {
	fixableRules = make(map[string]bool, len(autofix.Registry))
	for id := range autofix.Registry {
		fixableRules[id] = true
	}
}

// UpsertRepo inserts or updates a repository record. Returns the repo ID.
func (d *DB) UpsertRepo(owner, name string, stars int, language string) (int64, error) {
	fullName := owner + "/" + name
	_, err := d.db.Exec(`
		INSERT INTO repos (owner, name, full_name, stars, language)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(full_name) DO UPDATE SET stars=excluded.stars, language=excluded.language
	`, owner, name, fullName, stars, language)
	if err != nil {
		return 0, fmt.Errorf("tracking: upserting repo %s: %w", fullName, err)
	}

	var id int64
	err = d.db.QueryRow("SELECT id FROM repos WHERE full_name = ?", fullName).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("tracking: getting repo ID for %s: %w", fullName, err)
	}
	return id, nil
}

// GetRepoByFullName looks up a repo. Returns nil, nil if not found.
func (d *DB) GetRepoByFullName(fullName string) (*Repo, error) {
	r := &Repo{}
	err := d.db.QueryRow(
		"SELECT id, owner, name, full_name, stars, language FROM repos WHERE full_name = ?",
		fullName,
	).Scan(&r.ID, &r.Owner, &r.Name, &r.FullName, &r.Stars, &r.Language)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tracking: getting repo %s: %w", fullName, err)
	}
	return r, nil
}

// GetPendingRepos returns repos that have never been successfully scanned.
func (d *DB) GetPendingRepos(limit int) ([]Repo, error) {
	rows, err := d.db.Query(`
		SELECT r.id, r.owner, r.name, r.full_name, r.stars, r.language
		FROM repos r
		WHERE NOT EXISTS (
			SELECT 1 FROM scans s WHERE s.repo_id = r.id AND s.status IN ('completed', 'no_workflows')
		)
		ORDER BY r.stars DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("tracking: getting pending repos: %w", err)
	}
	defer rows.Close()
	return scanRepoRows(rows)
}

// GetErroredRepos returns repos whose last scan errored (for retry).
func (d *DB) GetErroredRepos(limit int) ([]Repo, error) {
	rows, err := d.db.Query(`
		SELECT r.id, r.owner, r.name, r.full_name, r.stars, r.language
		FROM repos r
		WHERE EXISTS (
			SELECT 1 FROM scans s WHERE s.repo_id = r.id AND s.status = 'error'
		)
		AND NOT EXISTS (
			SELECT 1 FROM scans s WHERE s.repo_id = r.id AND s.status IN ('completed', 'no_workflows')
		)
		ORDER BY r.stars DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("tracking: getting errored repos: %w", err)
	}
	defer rows.Close()
	return scanRepoRows(rows)
}

// RepoCount returns the total number of repos in the database.
func (d *DB) RepoCount() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM repos").Scan(&count)
	return count, err
}

// InsertScan creates a new scan record. Returns the scan ID.
func (d *DB) InsertScan(repoID int64, status ScanStatus, durationMs int64, errorMsg string) (int64, error) {
	result, err := d.db.Exec(`
		INSERT INTO scans (repo_id, status, duration_ms, error_msg)
		VALUES (?, ?, ?, ?)
	`, repoID, string(status), durationMs, errorMsg)
	if err != nil {
		return 0, fmt.Errorf("tracking: inserting scan for repo %d: %w", repoID, err)
	}
	return result.LastInsertId()
}

// InsertFindingsRaw bulk-inserts findings using raw field values.
func (d *DB) InsertFindingsRaw(scanID int64, findings []ScanFinding) error {
	if len(findings) == 0 {
		return nil
	}
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("tracking: beginning transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO findings (scan_id, rule_id, severity, workflow_file, line_number, is_fixable, is_fixed)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("tracking: preparing findings insert: %w", err)
	}
	defer stmt.Close()

	for _, f := range findings {
		isFixable := 0
		if f.IsFixable {
			isFixable = 1
		}
		isFixed := 0
		if f.IsFixed {
			isFixed = 1
		}
		if _, err := stmt.Exec(scanID, f.RuleID, f.Severity, f.WorkflowFile, f.LineNumber, isFixable, isFixed); err != nil {
			return fmt.Errorf("tracking: inserting finding %s: %w", f.RuleID, err)
		}
	}
	return tx.Commit()
}

// InsertFinding inserts a single finding record.
func (d *DB) InsertFinding(scanID int64, ruleID, severity, workflowFile string, lineNumber int) error {
	isFixable := 0
	if fixableRules[ruleID] {
		isFixable = 1
	}
	_, err := d.db.Exec(`
		INSERT INTO findings (scan_id, rule_id, severity, workflow_file, line_number, is_fixable)
		VALUES (?, ?, ?, ?, ?, ?)
	`, scanID, ruleID, severity, workflowFile, lineNumber, isFixable)
	return err
}

// InsertPR creates a pull request record.
func (d *DB) InsertPR(repoID int64, forkName, branch, prURL string, prNumber int) (int64, error) {
	result, err := d.db.Exec(`
		INSERT INTO pull_requests (repo_id, fork_name, branch, pr_url, pr_number, status)
		VALUES (?, ?, ?, ?, ?, 'open')
	`, repoID, forkName, branch, prURL, prNumber)
	if err != nil {
		return 0, fmt.Errorf("tracking: inserting PR for repo %d: %w", repoID, err)
	}
	return result.LastInsertId()
}

// UpdatePRStatus updates the status of a pull request.
func (d *DB) UpdatePRStatus(prID int64, status string) error {
	_, err := d.db.Exec(
		"UPDATE pull_requests SET status = ?, updated_at = datetime('now') WHERE id = ?",
		status, prID,
	)
	return err
}

// --- Analytics Queries ---

// GetOverviewStats returns the top-level statistics dashboard.
func (d *DB) GetOverviewStats() (*OverviewStats, error) {
	stats := &OverviewStats{}

	d.db.QueryRow("SELECT COUNT(*) FROM repos").Scan(&stats.TotalRepos)

	d.db.QueryRow(`
		SELECT COUNT(DISTINCT repo_id) FROM scans WHERE status IN ('completed', 'no_workflows')
	`).Scan(&stats.ScannedRepos)

	d.db.QueryRow(`
		SELECT COUNT(DISTINCT s.repo_id)
		FROM scans s
		JOIN findings f ON f.scan_id = s.id
		WHERE s.status = 'completed'
	`).Scan(&stats.ReposWithFindings)

	var critical, high, medium, low sql.NullInt64
	d.db.QueryRow(`
		SELECT
			SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END),
			SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END),
			SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END),
			SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END)
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		WHERE s.id IN (
			SELECT MAX(id) FROM scans WHERE status = 'completed' GROUP BY repo_id
		)
	`).Scan(&critical, &high, &medium, &low)
	stats.Severity.Critical = int(critical.Int64)
	stats.Severity.High = int(high.Int64)
	stats.Severity.Medium = int(medium.Int64)
	stats.Severity.Low = int(low.Int64)
	stats.TotalFindings = stats.Severity.Critical + stats.Severity.High + stats.Severity.Medium + stats.Severity.Low

	if stats.ScannedRepos > 0 {
		stats.VulnRate = float64(stats.ReposWithFindings) / float64(stats.ScannedRepos) * 100
	}

	var fixable, fixed sql.NullInt64
	d.db.QueryRow(`
		SELECT
			SUM(CASE WHEN is_fixable = 1 THEN 1 ELSE 0 END),
			SUM(CASE WHEN is_fixed = 1 THEN 1 ELSE 0 END)
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		WHERE s.id IN (
			SELECT MAX(id) FROM scans WHERE status = 'completed' GROUP BY repo_id
		)
	`).Scan(&fixable, &fixed)
	if fixable.Int64 > 0 {
		stats.FixRate = float64(fixed.Int64) / float64(fixable.Int64) * 100
	}

	d.db.QueryRow("SELECT COUNT(*) FROM pull_requests WHERE status = 'merged'").Scan(&stats.PRsMerged)
	d.db.QueryRow("SELECT COUNT(*) FROM pull_requests WHERE status = 'open'").Scan(&stats.PRsOpen)
	d.db.QueryRow("SELECT COUNT(*) FROM pull_requests WHERE status = 'closed'").Scan(&stats.PRsClosed)

	return stats, nil
}

// GetTopRules returns the most frequently triggered rules.
func (d *DB) GetTopRules(limit int) ([]RuleFrequency, error) {
	var total int
	d.db.QueryRow(`
		SELECT COUNT(*) FROM findings f
		JOIN scans s ON s.id = f.scan_id
		WHERE s.id IN (
			SELECT MAX(id) FROM scans WHERE status = 'completed' GROUP BY repo_id
		)
	`).Scan(&total)

	rows, err := d.db.Query(`
		SELECT f.rule_id, f.severity, COUNT(*) as cnt
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		WHERE s.id IN (
			SELECT MAX(id) FROM scans WHERE status = 'completed' GROUP BY repo_id
		)
		GROUP BY f.rule_id
		ORDER BY cnt DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("tracking: getting top rules: %w", err)
	}
	defer rows.Close()

	var results []RuleFrequency
	for rows.Next() {
		var rf RuleFrequency
		if err := rows.Scan(&rf.RuleID, &rf.Severity, &rf.Count); err != nil {
			return nil, err
		}
		if total > 0 {
			rf.Percent = float64(rf.Count) / float64(total) * 100
		}
		results = append(results, rf)
	}
	return results, rows.Err()
}

// GetLanguageStats returns per-language vulnerability statistics.
func (d *DB) GetLanguageStats(limit int) ([]LanguageStats, error) {
	rows, err := d.db.Query(`
		SELECT
			r.language,
			COUNT(DISTINCT r.id) as repo_count,
			COUNT(f.id) as finding_count,
			CAST(COUNT(DISTINCT CASE WHEN f.id IS NOT NULL THEN r.id END) AS REAL)
				/ NULLIF(COUNT(DISTINCT r.id), 0) * 100 as vuln_rate,
			CAST(COUNT(f.id) AS REAL) / NULLIF(COUNT(DISTINCT r.id), 0) as avg_findings
		FROM repos r
		JOIN scans s ON s.repo_id = r.id
		LEFT JOIN findings f ON f.scan_id = s.id
		WHERE s.id IN (
			SELECT MAX(id) FROM scans WHERE status = 'completed' GROUP BY repo_id
		)
		AND r.language != ''
		GROUP BY r.language
		HAVING repo_count >= 3
		ORDER BY finding_count DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("tracking: getting language stats: %w", err)
	}
	defer rows.Close()

	var results []LanguageStats
	for rows.Next() {
		var ls LanguageStats
		if err := rows.Scan(&ls.Language, &ls.RepoCount, &ls.FindingCount, &ls.VulnRate, &ls.AvgFindings); err != nil {
			return nil, err
		}
		results = append(results, ls)
	}
	return results, rows.Err()
}

// GetTimeline returns daily cumulative scan progress.
func (d *DB) GetTimeline() ([]TimelinePoint, error) {
	rows, err := d.db.Query(`
		SELECT
			DATE(s.scanned_at) as scan_date,
			COUNT(DISTINCT s.repo_id) as daily_repos,
			(SELECT COUNT(*) FROM findings f2
			 JOIN scans s2 ON s2.id = f2.scan_id
			 WHERE DATE(s2.scanned_at) <= DATE(s.scanned_at)
			 AND s2.status = 'completed') as cumulative_findings
		FROM scans s
		WHERE s.status IN ('completed', 'no_workflows')
		GROUP BY scan_date
		ORDER BY scan_date
	`)
	if err != nil {
		return nil, fmt.Errorf("tracking: getting timeline: %w", err)
	}
	defer rows.Close()

	var results []TimelinePoint
	cumulativeRepos := 0
	for rows.Next() {
		var tp TimelinePoint
		var dailyRepos int
		if err := rows.Scan(&tp.Date, &dailyRepos, &tp.FindingsTotal); err != nil {
			return nil, err
		}
		cumulativeRepos += dailyRepos
		tp.ReposScanned = cumulativeRepos
		results = append(results, tp)
	}
	return results, rows.Err()
}

// scanRepoRows is a helper to scan rows into []Repo.
func scanRepoRows(rows *sql.Rows) ([]Repo, error) {
	var repos []Repo
	for rows.Next() {
		var r Repo
		if err := rows.Scan(&r.ID, &r.Owner, &r.Name, &r.FullName, &r.Stars, &r.Language); err != nil {
			return nil, err
		}
		repos = append(repos, r)
	}
	return repos, rows.Err()
}
