package tracking

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB connection to the tracking SQLite database.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) a SQLite database at the given path.
// It runs migrations to ensure the schema is up-to-date.
func Open(path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("tracking: creating directory %s: %w", dir, err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("tracking: opening database %s: %w", path, err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("tracking: setting WAL mode: %w", err)
	}

	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("tracking: enabling foreign keys: %w", err)
	}

	tdb := &DB{db: db}
	if err := tdb.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return tdb, nil
}

// OpenMemory opens an in-memory SQLite database for testing.
func OpenMemory() (*DB, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("tracking: opening in-memory database: %w", err)
	}

	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, err
	}

	tdb := &DB{db: db}
	if err := tdb.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return tdb, nil
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// migrate runs schema migrations using a version table.
func (d *DB) migrate() error {
	_, err := d.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY
	)`)
	if err != nil {
		return fmt.Errorf("tracking: creating schema_version table: %w", err)
	}

	var currentVersion int
	row := d.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version")
	if err := row.Scan(&currentVersion); err != nil {
		return fmt.Errorf("tracking: reading schema version: %w", err)
	}

	for i, m := range migrations {
		ver := i + 1
		if ver <= currentVersion {
			continue
		}
		if _, err := d.db.Exec(m); err != nil {
			return fmt.Errorf("tracking: migration %d failed: %w", ver, err)
		}
		if _, err := d.db.Exec("INSERT INTO schema_version (version) VALUES (?)", ver); err != nil {
			return fmt.Errorf("tracking: recording migration %d: %w", ver, err)
		}
	}
	return nil
}

var migrations = []string{
	// Version 1: initial schema
	`CREATE TABLE repos (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		owner     TEXT    NOT NULL,
		name      TEXT    NOT NULL,
		full_name TEXT    NOT NULL UNIQUE,
		stars     INTEGER NOT NULL DEFAULT 0,
		language  TEXT    NOT NULL DEFAULT ''
	);
	CREATE INDEX idx_repos_stars ON repos(stars DESC);
	CREATE INDEX idx_repos_language ON repos(language);

	CREATE TABLE scans (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		repo_id     INTEGER NOT NULL REFERENCES repos(id),
		scanned_at  TEXT    NOT NULL DEFAULT (datetime('now')),
		status      TEXT    NOT NULL DEFAULT 'pending',
		duration_ms INTEGER NOT NULL DEFAULT 0,
		error_msg   TEXT    NOT NULL DEFAULT ''
	);
	CREATE INDEX idx_scans_repo_id ON scans(repo_id);
	CREATE INDEX idx_scans_scanned_at ON scans(scanned_at);

	CREATE TABLE findings (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id       INTEGER NOT NULL REFERENCES scans(id),
		rule_id       TEXT    NOT NULL,
		severity      TEXT    NOT NULL,
		workflow_file TEXT    NOT NULL,
		line_number   INTEGER NOT NULL DEFAULT 0,
		is_fixable    INTEGER NOT NULL DEFAULT 0,
		is_fixed      INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX idx_findings_scan_id ON findings(scan_id);
	CREATE INDEX idx_findings_rule_id ON findings(rule_id);
	CREATE INDEX idx_findings_severity ON findings(severity);

	CREATE TABLE pull_requests (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		repo_id    INTEGER NOT NULL REFERENCES repos(id),
		fork_name  TEXT    NOT NULL DEFAULT '',
		branch     TEXT    NOT NULL DEFAULT '',
		pr_url     TEXT    NOT NULL DEFAULT '',
		pr_number  INTEGER NOT NULL DEFAULT 0,
		status     TEXT    NOT NULL DEFAULT 'open',
		created_at TEXT    NOT NULL DEFAULT (datetime('now')),
		updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
	);
	CREATE INDEX idx_pull_requests_repo_id ON pull_requests(repo_id);`,
}
