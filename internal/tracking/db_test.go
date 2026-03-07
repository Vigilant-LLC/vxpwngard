package tracking

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpen_MigratesSchema(t *testing.T) {
	db := openTestDB(t)

	var version int
	err := db.db.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&version)
	require.NoError(t, err)
	assert.Equal(t, 1, version)
}

func TestUpsertRepo(t *testing.T) {
	db := openTestDB(t)

	id1, err := db.UpsertRepo("torvalds", "linux", 150000, "C")
	require.NoError(t, err)
	assert.Greater(t, id1, int64(0))

	// Upsert same repo — should return same ID with updated stars.
	id2, err := db.UpsertRepo("torvalds", "linux", 160000, "C")
	require.NoError(t, err)
	assert.Equal(t, id1, id2)

	repo, err := db.GetRepoByFullName("torvalds/linux")
	require.NoError(t, err)
	require.NotNil(t, repo)
	assert.Equal(t, 160000, repo.Stars)
}

func TestGetRepoByFullName_NotFound(t *testing.T) {
	db := openTestDB(t)

	repo, err := db.GetRepoByFullName("nonexistent/repo")
	require.NoError(t, err)
	assert.Nil(t, repo)
}

func TestInsertScan(t *testing.T) {
	db := openTestDB(t)

	repoID, err := db.UpsertRepo("foo", "bar", 100, "Go")
	require.NoError(t, err)

	scanID, err := db.InsertScan(repoID, StatusCompleted, 1500, "")
	require.NoError(t, err)
	assert.Greater(t, scanID, int64(0))
}

func TestInsertFinding(t *testing.T) {
	db := openTestDB(t)

	repoID, _ := db.UpsertRepo("foo", "bar", 100, "Go")
	scanID, _ := db.InsertScan(repoID, StatusCompleted, 1500, "")

	err := db.InsertFinding(scanID, "VXS-002", "critical", "ci.yml", 10)
	require.NoError(t, err)

	err = db.InsertFinding(scanID, "VXS-007", "high", "ci.yml", 20)
	require.NoError(t, err)
}

func TestInsertFindingsRaw(t *testing.T) {
	db := openTestDB(t)

	repoID, _ := db.UpsertRepo("foo", "bar", 100, "Go")
	scanID, _ := db.InsertScan(repoID, StatusCompleted, 1500, "")

	findings := []ScanFinding{
		{RuleID: "VXS-002", Severity: "critical", WorkflowFile: "ci.yml", LineNumber: 10, IsFixable: true},
		{RuleID: "VXS-007", Severity: "high", WorkflowFile: "ci.yml", LineNumber: 20, IsFixable: true},
		{RuleID: "VXS-012", Severity: "medium", WorkflowFile: "ci.yml", LineNumber: 30, IsFixable: false},
	}

	err := db.InsertFindingsRaw(scanID, findings)
	require.NoError(t, err)
}

func TestGetPendingRepos(t *testing.T) {
	db := openTestDB(t)

	db.UpsertRepo("a", "repo1", 100, "Go")
	id2, _ := db.UpsertRepo("b", "repo2", 200, "Python")
	db.UpsertRepo("c", "repo3", 50, "Rust")

	// Scan repo2 — it should no longer be pending.
	db.InsertScan(id2, StatusCompleted, 1000, "")

	pending, err := db.GetPendingRepos(10)
	require.NoError(t, err)
	assert.Len(t, pending, 2)
	// Should be ordered by stars DESC.
	assert.Equal(t, "a/repo1", pending[0].FullName)
	assert.Equal(t, "c/repo3", pending[1].FullName)
}

func TestGetOverviewStats(t *testing.T) {
	db := openTestDB(t)

	id1, _ := db.UpsertRepo("a", "repo1", 100, "Go")
	id2, _ := db.UpsertRepo("b", "repo2", 200, "Python")
	db.UpsertRepo("c", "repo3", 50, "Rust") // never scanned

	scan1, _ := db.InsertScan(id1, StatusCompleted, 1000, "")
	db.InsertFinding(scan1, "VXS-002", "critical", "ci.yml", 10)
	db.InsertFinding(scan1, "VXS-007", "high", "ci.yml", 20)
	db.InsertFinding(scan1, "VXS-012", "medium", "ci.yml", 30)

	db.InsertScan(id2, StatusNoWorkflows, 500, "")

	stats, err := db.GetOverviewStats()
	require.NoError(t, err)
	assert.Equal(t, 3, stats.TotalRepos)
	assert.Equal(t, 2, stats.ScannedRepos)
	assert.Equal(t, 1, stats.ReposWithFindings)
	assert.Equal(t, 3, stats.TotalFindings)
	assert.Equal(t, 1, stats.Severity.Critical)
	assert.Equal(t, 1, stats.Severity.High)
	assert.Equal(t, 1, stats.Severity.Medium)
	assert.InDelta(t, 50.0, stats.VulnRate, 0.1)
}

func TestGetTopRules(t *testing.T) {
	db := openTestDB(t)

	id1, _ := db.UpsertRepo("a", "repo1", 100, "Go")
	scan1, _ := db.InsertScan(id1, StatusCompleted, 1000, "")
	db.InsertFinding(scan1, "VXS-007", "high", "ci.yml", 10)
	db.InsertFinding(scan1, "VXS-007", "high", "ci.yml", 20)
	db.InsertFinding(scan1, "VXS-002", "critical", "ci.yml", 30)

	rules, err := db.GetTopRules(10)
	require.NoError(t, err)
	assert.Len(t, rules, 2)
	assert.Equal(t, "VXS-007", rules[0].RuleID)
	assert.Equal(t, 2, rules[0].Count)
}

func TestGetLanguageStats(t *testing.T) {
	db := openTestDB(t)

	// Create 3 Go repos with findings.
	for i := 1; i <= 3; i++ {
		id, _ := db.UpsertRepo("owner", fmt.Sprintf("go-repo%d", i), 100, "Go")
		scanID, _ := db.InsertScan(id, StatusCompleted, 1000, "")
		db.InsertFinding(scanID, "VXS-007", "high", "ci.yml", 10)
	}

	stats, err := db.GetLanguageStats(10)
	require.NoError(t, err)
	assert.Len(t, stats, 1)
	assert.Equal(t, "Go", stats[0].Language)
	assert.Equal(t, 3, stats[0].RepoCount)
	assert.Equal(t, 3, stats[0].FindingCount)
}

func TestInsertPR(t *testing.T) {
	db := openTestDB(t)

	repoID, _ := db.UpsertRepo("foo", "bar", 100, "Go")
	prID, err := db.InsertPR(repoID, "dagecko/bar", "vxpwngard/fix-ci-security", "https://github.com/foo/bar/pull/1", 1)
	require.NoError(t, err)
	assert.Greater(t, prID, int64(0))

	err = db.UpdatePRStatus(prID, "merged")
	require.NoError(t, err)
}

func TestRepoCount(t *testing.T) {
	db := openTestDB(t)

	count, err := db.RepoCount()
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	db.UpsertRepo("a", "b", 100, "Go")
	db.UpsertRepo("c", "d", 200, "Python")

	count, err = db.RepoCount()
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}
