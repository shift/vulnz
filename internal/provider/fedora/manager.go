package fedora

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	vulnzhttp "github.com/shift/vulnz/internal/http"
	"github.com/shift/vulnz/internal/provider"
)

var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d+`)

type bodhiResponse struct {
	Updates []bodhiUpdate `json:"updates"`
	Pages   int           `json:"pages"`
}

type bodhiUpdate struct {
	Alias    string       `json:"alias"`
	Title    string       `json:"title"`
	Released string       `json:"released"`
	Status   string       `json:"status"`
	Type     string       `json:"type"`
	Severity string       `json:"severity"`
	Notes    string       `json:"notes"`
	URL      string       `json:"url"`
	Builds   []bodhiBuild `json:"builds"`
	Bugs     []bodhiBug   `json:"bugs"`
	Release  bodhiRelease `json:"release"`
}

type bodhiBuild struct {
	NVR   string `json:"nvr"`
	Epoch int    `json:"epoch"`
	Type  string `json:"type"`
}

type bodhiBug struct {
	BugID    int    `json:"bug_id"`
	Title    string `json:"title"`
	Security bool   `json:"security"`
}

type bodhiRelease struct {
	Version string `json:"version"`
}

type fixedInEntry struct {
	Name           string         `json:"Name"`
	Version        string         `json:"Version"`
	VersionFormat  string         `json:"VersionFormat"`
	NamespaceName  string         `json:"NamespaceName"`
	Module         string         `json:"Module"`
	VendorAdvisory vendorAdvisory `json:"VendorAdvisory"`
}

type vendorAdvisory struct {
	NoAdvisory      bool              `json:"NoAdvisory"`
	AdvisorySummary []advisorySummary `json:"AdvisorySummary"`
}

type advisorySummary struct {
	ID   string `json:"ID"`
	Link string `json:"Link"`
}

type Manager struct {
	baseURL string
	config  provider.Config
	client  *http.Client
	urls    []string
}

func NewManager(config provider.Config) *Manager {
	return NewManagerWithURL(DefaultURL, config)
}

func NewManagerWithURL(baseURL string, config provider.Config) *Manager {
	return &Manager{
		baseURL: baseURL,
		config:  config,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

func (m *Manager) URLs() []string {
	return m.urls
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	records := make(map[string]map[string]interface{})
	page := 1

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		pageURL := fmt.Sprintf("%s/updates/?status=stable&type=security&rows_per_page=100&page=%d", m.baseURL, page)
		updates, totalPages, err := m.fetchPage(ctx, pageURL)
		if err != nil {
			return nil, fmt.Errorf("fetch page %d: %w", page, err)
		}

		m.urls = append(m.urls, pageURL)
		m.config.Logger.InfoContext(ctx, "fetched bodhi page",
			"url", pageURL,
			"page", page,
			"total_pages", totalPages,
			"updates_on_page", len(updates),
		)

		for _, update := range updates {
			updateRecords := m.parseUpdate(update)
			for vulnID, record := range updateRecords {
				if existing, ok := records[vulnID]; ok {
					existingVuln := existing["Vulnerability"].(map[string]interface{})
					newVuln := record["Vulnerability"].(map[string]interface{})
					existingFixedIn := existingVuln["FixedIn"].([]interface{})
					newFixedIn := newVuln["FixedIn"].([]interface{})
					existingVuln["FixedIn"] = append(existingFixedIn, newFixedIn...)
				} else {
					records[vulnID] = record
				}
			}
		}

		if page >= totalPages {
			break
		}
		page++
	}

	return records, nil
}

func (m *Manager) fetchPage(ctx context.Context, pageURL string) ([]bodhiUpdate, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch data: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := vulnzhttp.ReadLimitedBody(resp)
	if err != nil {
		return nil, 0, fmt.Errorf("read response: %w", err)
	}

	var bodhiResp bodhiResponse
	if err := json.Unmarshal(body, &bodhiResp); err != nil {
		return nil, 0, fmt.Errorf("parse JSON: %w", err)
	}

	if bodhiResp.Pages == 0 {
		bodhiResp.Pages = 1
	}

	return bodhiResp.Updates, bodhiResp.Pages, nil
}

func (m *Manager) parseUpdate(update bodhiUpdate) map[string]map[string]interface{} {
	alias := update.Alias
	if alias == "" {
		return nil
	}

	release := m.extractRelease(update)
	if release == "" {
		return nil
	}

	namespace := "fedora:" + release
	severity := normalizeSeverity(update.Severity)
	cves := extractCVEs(update)
	link := update.URL
	if link == "" {
		link = fmt.Sprintf("%s/updates/%s", m.baseURL, alias)
	}

	packages := parseBuilds(update, release, namespace, alias, link, m.config.Logger)
	if len(packages) == 0 {
		return nil
	}

	baseRecord := map[string]interface{}{
		"Vulnerability": map[string]interface{}{
			"Severity":      severity,
			"NamespaceName": namespace,
			"FixedIn":       packages,
			"Link":          link,
			"Description":   update.Notes,
			"Metadata": map[string]interface{}{
				"Issued":  update.Released,
				"Updated": update.Released,
			},
			"Name": "",
			"CVSS": []interface{}{},
		},
	}

	result := make(map[string]map[string]interface{})

	if len(cves) > 0 {
		for _, cveID := range cves {
			record := deepCopyRecord(baseRecord)
			vuln := record["Vulnerability"].(map[string]interface{})
			vuln["Name"] = cveID
			metadata := vuln["Metadata"].(map[string]interface{})
			metadata["CVE"] = []interface{}{
				map[string]interface{}{
					"Name": cveID,
					"Link": fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID),
				},
			}
			result[namespace+"/"+cveID] = record
		}
	} else {
		record := deepCopyRecord(baseRecord)
		vuln := record["Vulnerability"].(map[string]interface{})
		vuln["Name"] = alias
		metadata := vuln["Metadata"].(map[string]interface{})
		metadata["CVE"] = []interface{}{}
		result[namespace+"/"+alias] = record
	}

	return result
}

func (m *Manager) extractRelease(update bodhiUpdate) string {
	if update.Release.Version != "" && isDigit(update.Release.Version) {
		return update.Release.Version
	}

	for _, build := range update.Builds {
		release := extractReleaseFromNVR(build.NVR)
		if release != "" {
			return release
		}
	}

	return ""
}

func extractReleaseFromNVR(nvr string) string {
	parts := strings.SplitN(nvr, "-", 3)
	if len(parts) != 3 {
		return ""
	}

	rel := parts[2]
	dotParts := strings.SplitN(rel, ".", 2)
	if len(dotParts) < 1 {
		return ""
	}

	suffix := dotParts[0]
	if strings.HasPrefix(suffix, "fc") && len(suffix) > 2 {
		release := suffix[2:]
		if isDigit(release) {
			return release
		}
	}

	return ""
}

func extractCVEs(update bodhiUpdate) []string {
	var cves []string
	seen := make(map[string]bool)

	for _, bug := range update.Bugs {
		if !bug.Security {
			continue
		}
		for _, match := range cvePattern.FindAllString(bug.Title, -1) {
			if !seen[match] {
				seen[match] = true
				cves = append(cves, match)
			}
		}
	}

	if len(cves) == 0 {
		for _, field := range []string{update.Title} {
			for _, match := range cvePattern.FindAllString(field, -1) {
				if !seen[match] {
					seen[match] = true
					cves = append(cves, match)
				}
			}
		}
	}

	return cves
}

func parseBuilds(update bodhiUpdate, release, namespace, alias, link string, logger interface {
	InfoContext(context.Context, string, ...any)
}) []interface{} {
	var packages []interface{}

	for _, build := range update.Builds {
		if build.Type != "" && build.Type != "rpm" {
			continue
		}

		name, version, rel, ok := parseNVR(build.NVR)
		if !ok {
			continue
		}

		epoch := build.Epoch
		fullVersion := fmt.Sprintf("%d:%s-%s", epoch, version, rel)

		entry := fixedInEntry{
			Name:          name,
			Version:       fullVersion,
			VersionFormat: "rpm",
			NamespaceName: namespace,
			Module:        "",
			VendorAdvisory: vendorAdvisory{
				NoAdvisory: false,
				AdvisorySummary: []advisorySummary{
					{ID: alias, Link: link},
				},
			},
		}

		pkgMap, err := structToMap(entry)
		if err != nil {
			continue
		}
		packages = append(packages, pkgMap)
	}

	return packages
}

func parseNVR(nvr string) (name, version, release string, ok bool) {
	parts := strings.SplitN(nvr, "-", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "urgent", "critical":
		return "Critical"
	case "important", "high":
		return "High"
	case "moderate", "medium":
		return "Medium"
	case "low":
		return "Low"
	case "none", "unspecified", "":
		return "Unknown"
	default:
		return "Unknown"
	}
}

func isDigit(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func deepCopyRecord(src map[string]interface{}) map[string]interface{} {
	data, err := json.Marshal(src)
	if err != nil {
		return map[string]interface{}{}
	}
	var dst map[string]interface{}
	if err := json.Unmarshal(data, &dst); err != nil {
		return map[string]interface{}{}
	}
	return dst
}

func TestParseNVR(nvr string) (name, version, release string, ok bool) {
	return parseNVR(nvr)
}

func TestExtractCVEs(bugs []map[string]interface{}, title string) []string {
	b := make([]bodhiBug, len(bugs))
	for i, bug := range bugs {
		bugID := 0
		if v, ok := bug["bug_id"]; ok {
			bugID = v.(int)
		}
		b[i] = bodhiBug{
			BugID:    bugID,
			Title:    bug["title"].(string),
			Security: bug["security"].(bool),
		}
	}
	return extractCVEs(bodhiUpdate{Bugs: b, Title: title})
}

func TestNormalizeSeverity(severity string) string {
	return normalizeSeverity(severity)
}

func structToMap(s interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}
