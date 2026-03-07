package tracking

import "time"

// ScanStatus represents the outcome of a scan attempt.
type ScanStatus string

const (
	StatusPending     ScanStatus = "pending"
	StatusCompleted   ScanStatus = "completed"
	StatusError       ScanStatus = "error"
	StatusNoWorkflows ScanStatus = "no_workflows"
)

// Repo represents a GitHub repository in the target list.
type Repo struct {
	ID       int64
	Owner    string
	Name     string
	FullName string // "owner/name"
	Stars    int
	Language string
}

// Scan represents a single scan of a repository.
type Scan struct {
	ID         int64
	RepoID     int64
	ScannedAt  time.Time
	Status     ScanStatus
	DurationMs int64
	Error      string
}

// ScanFinding represents a single finding from a scan.
type ScanFinding struct {
	ID           int64
	ScanID       int64
	RuleID       string
	Severity     string
	WorkflowFile string
	LineNumber   int
	IsFixable    bool
	IsFixed      bool
}

// PullRequest tracks a remediation PR sent to a repository.
type PullRequest struct {
	ID        int64
	RepoID    int64
	ForkName  string
	Branch    string
	PRURL     string
	PRNumber  int
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// OverviewStats holds the top-level numbers for the stats dashboard.
type OverviewStats struct {
	TotalRepos        int
	ScannedRepos      int
	ReposWithFindings int
	TotalFindings     int
	Severity          SeverityBreakdown
	VulnRate          float64
	FixRate           float64
	PRsMerged         int
	PRsOpen           int
	PRsClosed         int
}

// SeverityBreakdown holds counts by severity level.
type SeverityBreakdown struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// RuleFrequency holds the count of findings for a specific rule.
type RuleFrequency struct {
	RuleID   string
	Severity string
	Count    int
	Percent  float64
}

// LanguageStats holds aggregated scan stats for a specific language.
type LanguageStats struct {
	Language     string
	RepoCount    int
	FindingCount int
	VulnRate     float64
	AvgFindings  float64
}

// TimelinePoint represents scan progress at a point in time.
type TimelinePoint struct {
	Date          string
	ReposScanned  int
	FindingsTotal int
}

// StatsJSON is the JSON-serializable form of all analytics.
type StatsJSON struct {
	Overview  *OverviewStats  `json:"overview"`
	TopRules  []RuleFrequency `json:"top_rules"`
	Languages []LanguageStats `json:"languages"`
	Timeline  []TimelinePoint `json:"timeline"`
}
