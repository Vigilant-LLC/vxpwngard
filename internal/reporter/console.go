package reporter

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/Vigilant-LLC/vxpwngard/internal/rules"
)

// ReportConsole writes color-coded findings to the provided writer.
// When noColor is true, ANSI escape codes are suppressed.
// When isDemo is true and a finding carries DemoContext, the context is
// printed immediately after the finding. The Vigilant footer is
// suppressed in demo mode.
func ReportConsole(w io.Writer, findings []rules.Finding, noColor bool, duration time.Duration, isDemo bool) {
	color.NoColor = noColor

	// Color helpers — all output goes through the writer.
	boldRed := color.New(color.FgRed, color.Bold).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	boldWhite := color.New(color.FgWhite, color.Bold).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()
	gray := color.New(color.FgHiBlack).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	separator := strings.Repeat("\u2501", 58) // ━ heavy horizontal
	thinSep := strings.Repeat("\u2500", 58)   // ─ light horizontal

	severityColor := func(sev string) string {
		switch strings.ToLower(sev) {
		case "critical":
			return boldRed(strings.ToUpper(sev))
		case "high":
			return red(strings.ToUpper(sev))
		case "medium":
			return yellow(strings.ToUpper(sev))
		case "low":
			return cyan(strings.ToUpper(sev))
		default:
			return strings.ToUpper(sev)
		}
	}

	if len(findings) == 0 {
		fmt.Fprintln(w, green("\u2713 No issues found. Stay vigilant."))
		fmt.Fprintf(w, "\nScan completed in %s\n", duration)
		if !isDemo {
			printFooter(w, thinSep)
		}
		return
	}

	// Severity counters.
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, f := range findings {
		fmt.Fprintln(w, separator)

		// Header line: [CRITICAL] VXS-001 — rule name
		fmt.Fprintf(w, "[%s] %s \u2014 %s\n",
			severityColor(f.Severity),
			boldWhite(f.RuleID),
			f.RuleName,
		)

		// File line.
		fileLine := blue(f.File)
		if f.LineNumber > 0 {
			fileLine = fmt.Sprintf("%s (line %d)", blue(f.File), f.LineNumber)
		}
		fmt.Fprintf(w, "File:     %s\n", fileLine)

		// Job & Step (only if present).
		if f.JobID != "" {
			fmt.Fprintf(w, "Job:      %s\n", f.JobID)
		}
		if f.StepName != "" {
			fmt.Fprintf(w, "Step:     %s\n", f.StepName)
		}

		// Description — shown as Source/Sink pair when it contains " → ".
		if f.Description != "" {
			fmt.Fprintln(w)
			if strings.Contains(f.Description, "\u2192") {
				parts := strings.SplitN(f.Description, "\u2192", 2)
				if len(parts) == 2 {
					fmt.Fprintf(w, "Source:   %s\n", strings.TrimSpace(parts[0]))
					fmt.Fprintf(w, "Sink:     %s\n", strings.TrimSpace(parts[1]))
				} else {
					fmt.Fprintf(w, "Desc:     %s\n", f.Description)
				}
			} else {
				fmt.Fprintf(w, "Desc:     %s\n", f.Description)
			}
		}

		// Attack scenario.
		if f.AttackScenario != "" {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Attack:   %s\n", f.AttackScenario)
		}

		// Evidence.
		if f.Evidence != "" {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Evidence: %s\n", gray(f.Evidence))
		}

		// Fix.
		if f.Fix != "" {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Fix:")
			for _, line := range strings.Split(f.Fix, "\n") {
				fmt.Fprintf(w, "  %s\n", green(line))
			}
		}

		// References.
		if len(f.References) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Docs:     %s\n", strings.Join(f.References, ", "))
		}

		// Demo context.
		if isDemo && f.DemoContext != "" {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Demo:     %s\n", gray(f.DemoContext))
		}

		fmt.Fprintln(w, separator)
		fmt.Fprintln(w)

		counts[strings.ToLower(f.Severity)]++
	}

	// Summary line.
	fmt.Fprintf(w, "Summary: %s Critical | %s High | %s Medium | %s Low\n",
		boldRed(fmt.Sprintf("%d", counts["critical"])),
		red(fmt.Sprintf("%d", counts["high"])),
		yellow(fmt.Sprintf("%d", counts["medium"])),
		cyan(fmt.Sprintf("%d", counts["low"])),
	)

	fmt.Fprintf(w, "\nScan completed in %s\n", duration)

	if !isDemo {
		printFooter(w, thinSep)
	}
}

func printFooter(w io.Writer, sep string) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w, "Need forensic validation & remediation assurance?")
	fmt.Fprintln(w, "\u2192 Vigilant Pipeline Assessment: vigilantnow.com")
	fmt.Fprintln(w, sep)
}
