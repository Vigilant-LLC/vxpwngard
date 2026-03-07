package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// SearchResult represents a single repository from the GitHub Search API.
type SearchResult struct {
	FullName    string
	Owner       string
	Name        string
	Stars       int
	Language    string
	Description string
}

type searchResponse struct {
	TotalCount int          `json:"total_count"`
	Items      []searchItem `json:"items"`
}

type searchItem struct {
	FullName    string       `json:"full_name"`
	StarCount   int          `json:"stargazers_count"`
	Language    *string      `json:"language"`
	Description *string      `json:"description"`
	Owner       searchOwner  `json:"owner"`
	Name        string       `json:"name"`
}

type searchOwner struct {
	Login string `json:"login"`
}

// SearchOptions configures the repository search.
type SearchOptions struct {
	MinStars   int
	MaxStars   int      // 0 = no upper bound
	Languages  []string // empty = all
	PerPage    int      // default 100
	MaxResults int      // max results to return from this search
	Token      string   // GITHUB_TOKEN override
}

// starTier defines a star range for partitioned searching.
type starTier struct {
	Min int
	Max int // 0 = no upper bound
}

// topLanguages used for sub-partitioning crowded tiers.
var topLanguages = []string{
	"JavaScript", "Python", "TypeScript", "Java", "Go",
	"C++", "C", "Rust", "PHP", "Ruby",
	"C#", "Swift", "Kotlin", "Dart", "Shell",
	"Scala", "Lua", "Objective-C", "Haskell", "Elixir",
}

// SearchAllTiers performs the full target list generation by searching across
// multiple star tiers. Returns deduplicated results sorted by stars descending.
func SearchAllTiers(maxTargets int, minStars int, onProgress func(msg string)) ([]SearchResult, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable is required for target generation")
	}

	tiers := buildTiers(minStars)
	seen := make(map[string]bool)
	var allResults []SearchResult

	for _, tier := range tiers {
		if len(allResults) >= maxTargets {
			break
		}

		query := buildQuery(tier.Min, tier.Max, "")
		if onProgress != nil {
			onProgress(fmt.Sprintf("Searching: %s", query))
		}

		results, err := searchPages(token, query, 1000)
		if err != nil {
			if onProgress != nil {
				onProgress(fmt.Sprintf("  Warning: %v", err))
			}
			continue
		}

		added := 0
		for _, r := range results {
			if !seen[r.FullName] {
				seen[r.FullName] = true
				allResults = append(allResults, r)
				added++
			}
		}

		if onProgress != nil {
			onProgress(fmt.Sprintf("  Found %d repos (%d new, %d total)", len(results), added, len(allResults)))
		}

		// If we got 1000 results (the API max), subdivide by language.
		if len(results) >= 1000 {
			for _, lang := range topLanguages {
				if len(allResults) >= maxTargets {
					break
				}

				langQuery := buildQuery(tier.Min, tier.Max, lang)
				if onProgress != nil {
					onProgress(fmt.Sprintf("  Sub-search: %s", langQuery))
				}

				langResults, err := searchPages(token, langQuery, 1000)
				if err != nil {
					continue
				}

				langAdded := 0
				for _, r := range langResults {
					if !seen[r.FullName] {
						seen[r.FullName] = true
						allResults = append(allResults, r)
						langAdded++
					}
				}

				if langAdded > 0 && onProgress != nil {
					onProgress(fmt.Sprintf("    +%d new repos", langAdded))
				}

				// Rate limit: 30 search requests/min = 2s between requests.
				time.Sleep(2 * time.Second)
			}
		}
	}

	// Sort by stars descending.
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].Stars > allResults[j].Stars
	})

	// Trim to maxTargets.
	if len(allResults) > maxTargets {
		allResults = allResults[:maxTargets]
	}

	return allResults, nil
}

// buildTiers creates star-range partitions for the search.
func buildTiers(minStars int) []starTier {
	tiers := []starTier{
		{100000, 0},
		{50000, 99999},
		{20000, 49999},
		{10000, 19999},
		{5000, 9999},
		{2000, 4999},
		{1000, 1999},
		{500, 999},
	}

	// Filter to only tiers at or above minStars.
	var filtered []starTier
	for _, t := range tiers {
		if t.Max == 0 || t.Max >= minStars {
			if t.Min < minStars {
				t.Min = minStars
			}
			filtered = append(filtered, t)
		}
	}
	return filtered
}

// buildQuery constructs a GitHub search query string.
func buildQuery(minStars, maxStars int, language string) string {
	var parts []string

	if maxStars > 0 {
		parts = append(parts, fmt.Sprintf("stars:%d..%d", minStars, maxStars))
	} else {
		parts = append(parts, fmt.Sprintf("stars:>=%d", minStars))
	}

	if language != "" {
		parts = append(parts, fmt.Sprintf("language:%q", language))
	}

	// Only repos with GitHub Actions workflows.
	parts = append(parts, "path:.github/workflows")

	return strings.Join(parts, " ")
}

// searchPages fetches up to maxResults from a single search query, paginating.
func searchPages(token, query string, maxResults int) ([]SearchResult, error) {
	var results []SearchResult
	perPage := 100
	maxPages := (maxResults + perPage - 1) / perPage
	if maxPages > 10 {
		maxPages = 10 // GitHub API max: 1000 results = 10 pages of 100
	}

	for page := 1; page <= maxPages; page++ {
		pageResults, totalCount, err := searchPage(token, query, page, perPage)
		if err != nil {
			return results, err
		}

		results = append(results, pageResults...)

		// No more pages available.
		if len(results) >= totalCount || len(pageResults) < perPage {
			break
		}

		// Rate limiting: 2s between search requests.
		time.Sleep(2 * time.Second)
	}

	return results, nil
}

// searchPage fetches a single page of search results.
func searchPage(token, query string, page, perPage int) ([]SearchResult, int, error) {
	u := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc&per_page=%d&page=%d",
		url.QueryEscape(query), perPage, page)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("creating search request: %w", err)
	}

	req.Header.Set("User-Agent", "VXPwngard/0.1.0")
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("search request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("reading search response: %w", err)
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, 0, fmt.Errorf("rate limited (status %d), try again later", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("search API returned status %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	var sr searchResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, 0, fmt.Errorf("parsing search response: %w", err)
	}

	var results []SearchResult
	for _, item := range sr.Items {
		lang := ""
		if item.Language != nil {
			lang = *item.Language
		}
		desc := ""
		if item.Description != nil {
			desc = *item.Description
		}
		results = append(results, SearchResult{
			FullName:    item.FullName,
			Owner:       item.Owner.Login,
			Name:        item.Name,
			Stars:       item.StarCount,
			Language:    lang,
			Description: desc,
		})
	}

	return results, sr.TotalCount, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
