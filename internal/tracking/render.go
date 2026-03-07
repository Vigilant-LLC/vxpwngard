package tracking

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
)

// RenderOverview prints the top-level stats dashboard.
func RenderOverview(w io.Writer, stats *OverviewStats) {
	boldWhite := color.New(color.FgWhite, color.Bold).SprintFunc()
	boldRed := color.New(color.FgRed, color.Bold).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	gray := color.New(color.FgHiBlack).SprintFunc()

	sep := strings.Repeat("\u2501", 58)

	fmt.Fprintln(w, sep)
	fmt.Fprintln(w, boldWhite("  VXPwngard Research Scan \u2014 Dashboard"))
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w)

	// Scope section
	fmt.Fprintln(w, boldWhite("  SCOPE"))
	fmt.Fprintf(w, "  Target Repos:        %s\n", boldWhite(fmtNum(stats.TotalRepos)))
	fmt.Fprintf(w, "  Scanned:             %s  %s\n",
		boldWhite(fmtNum(stats.ScannedRepos)),
		gray(fmt.Sprintf("(%.1f%%)", pct(stats.ScannedRepos, stats.TotalRepos))))
	fmt.Fprintf(w, "  With Findings:       %s  %s\n",
		boldWhite(fmtNum(stats.ReposWithFindings)),
		gray(fmt.Sprintf("(%.1f%%)", stats.VulnRate)))
	fmt.Fprintln(w)

	// Findings section
	fmt.Fprintln(w, boldWhite("  FINDINGS"))
	fmt.Fprintf(w, "  Total:               %s\n", boldWhite(fmtNum(stats.TotalFindings)))

	maxSev := max(stats.Severity.Critical, stats.Severity.High, stats.Severity.Medium, stats.Severity.Low)
	if maxSev == 0 {
		maxSev = 1
	}

	printBar(w, "Critical", stats.Severity.Critical, maxSev, stats.TotalFindings, boldRed)
	printBar(w, "High", stats.Severity.High, maxSev, stats.TotalFindings, red)
	printBar(w, "Medium", stats.Severity.Medium, maxSev, stats.TotalFindings, yellow)
	printBar(w, "Low", stats.Severity.Low, maxSev, stats.TotalFindings, cyan)
	fmt.Fprintln(w)

	// Fix/PR section (only if there's data)
	if stats.FixRate > 0 || stats.PRsMerged > 0 || stats.PRsOpen > 0 {
		fmt.Fprintln(w, boldWhite("  REMEDIATION"))
		if stats.FixRate > 0 {
			fmt.Fprintf(w, "  Fix Rate:            %s\n", green(fmt.Sprintf("%.1f%%", stats.FixRate)))
		}
		if stats.PRsMerged > 0 || stats.PRsOpen > 0 || stats.PRsClosed > 0 {
			fmt.Fprintf(w, "  PRs Merged:          %s\n", green(fmtNum(stats.PRsMerged)))
			fmt.Fprintf(w, "  PRs Open:            %s\n", boldWhite(fmtNum(stats.PRsOpen)))
			fmt.Fprintf(w, "  PRs Closed:          %s\n", gray(fmtNum(stats.PRsClosed)))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, sep)
	fmt.Fprintln(w, gray("  Vigilant \u2014 vigilantnow.com"))
	fmt.Fprintln(w, sep)
}

// RenderTopRules prints the rule frequency table.
func RenderTopRules(w io.Writer, rules []RuleFrequency) {
	boldWhite := color.New(color.FgWhite, color.Bold).SprintFunc()
	gray := color.New(color.FgHiBlack).SprintFunc()

	fmt.Fprintln(w)
	fmt.Fprintln(w, boldWhite("  TOP RULES"))

	for i, r := range rules {
		sevColor := severityColorFunc(r.Severity)
		fmt.Fprintf(w, "  %s  %s  %s  %s\n",
			gray(fmt.Sprintf("#%-2d", i+1)),
			sevColor(fmt.Sprintf("%-7s", r.RuleID)),
			fmt.Sprintf("%6s", fmtNum(r.Count)),
			gray(fmt.Sprintf("(%.1f%%)", r.Percent)),
		)
	}
}

// RenderLanguageStats prints the language breakdown table.
func RenderLanguageStats(w io.Writer, stats []LanguageStats) {
	boldWhite := color.New(color.FgWhite, color.Bold).SprintFunc()
	gray := color.New(color.FgHiBlack).SprintFunc()

	fmt.Fprintln(w)
	fmt.Fprintln(w, boldWhite("  LANGUAGE BREAKDOWN"))

	for _, ls := range stats {
		fmt.Fprintf(w, "  %-14s %4d repos  %6s findings  %s vuln rate\n",
			boldWhite(ls.Language),
			ls.RepoCount,
			fmtNum(ls.FindingCount),
			gray(fmt.Sprintf("%.1f%%", ls.VulnRate)),
		)
	}
}

// RenderTimeline prints a simple ASCII timeline.
func RenderTimeline(w io.Writer, points []TimelinePoint) {
	boldWhite := color.New(color.FgWhite, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	fmt.Fprintln(w)
	fmt.Fprintln(w, boldWhite("  SCAN TIMELINE"))

	for _, p := range points {
		barLen := p.ReposScanned / 100
		if barLen > 40 {
			barLen = 40
		}
		if barLen < 1 && p.ReposScanned > 0 {
			barLen = 1
		}
		bar := strings.Repeat("\u2588", barLen)
		fmt.Fprintf(w, "  %s  %s %s repos, %s findings\n",
			p.Date, green(bar), fmtNum(p.ReposScanned), fmtNum(p.FindingsTotal))
	}
}

// --- helpers ---

func printBar(w io.Writer, label string, value, maxVal, total int, colorFn func(a ...interface{}) string) {
	barWidth := 20
	barLen := 0
	if maxVal > 0 {
		barLen = value * barWidth / maxVal
	}
	if barLen < 1 && value > 0 {
		barLen = 1
	}
	bar := strings.Repeat("\u2588", barLen)
	pctVal := float64(0)
	if total > 0 {
		pctVal = float64(value) / float64(total) * 100
	}
	fmt.Fprintf(w, "  %s %-8s %6s  %s\n",
		colorFn(bar+strings.Repeat(" ", barWidth-barLen)),
		label+":",
		fmtNum(value),
		color.New(color.FgHiBlack).Sprintf("(%4.1f%%)", pctVal),
	)
}

func severityColorFunc(sev string) func(a ...interface{}) string {
	switch strings.ToLower(sev) {
	case "critical":
		return color.New(color.FgRed, color.Bold).SprintFunc()
	case "high":
		return color.New(color.FgRed).SprintFunc()
	case "medium":
		return color.New(color.FgYellow).SprintFunc()
	case "low":
		return color.New(color.FgCyan).SprintFunc()
	default:
		return fmt.Sprint
	}
}

func fmtNum(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		if n%1000 == 0 {
			return fmt.Sprintf("%d,%03d", n/1000, 0)
		}
		return fmt.Sprintf("%d,%03d", n/1000, n%1000)
	}
	return fmt.Sprintf("%d,%03d,%03d", n/1000000, (n/1000)%1000, n%1000)
}

func pct(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) / float64(whole) * 100
}

func max(vals ...int) int {
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}
