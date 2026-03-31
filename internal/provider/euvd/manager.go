package euvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	vulnzhttp "github.com/shift/vulnz/internal/http"
	"github.com/shift/vulnz/internal/provider"
)

// EUVDRecord represents a single exploited vulnerability from the EUVD API.
type EUVDRecord struct {
	ID               string      `json:"id"`
	EnisaUUID        string      `json:"enisaUuid"`
	Description      string      `json:"description"`
	DatePublished    string      `json:"datePublished"`
	DateUpdated      string      `json:"dateUpdated"`
	BaseScore        float64     `json:"baseScore"`
	BaseScoreVersion string      `json:"baseScoreVersion"`
	BaseScoreVector  string      `json:"baseScoreVector"`
	References       string      `json:"references"`
	Aliases          string      `json:"aliases"`
	Assigner         string      `json:"assigner"`
	EPSS             float64     `json:"epss"`
	ExploitedSince   string      `json:"exploitedSince"`
	EnisaIDProduct   []IDProduct `json:"enisaIdProduct"`
	EnisaIDVendor    []IDVendor  `json:"enisaIdVendor"`
}

// IDProduct represents a product affected by a vulnerability.
type IDProduct struct {
	ID             string  `json:"id"`
	Product        Product `json:"product"`
	ProductVersion string  `json:"product_version"`
}

// Product represents a product name.
type Product struct {
	Name string `json:"name"`
}

// IDVendor represents a vendor associated with a vulnerability.
type IDVendor struct {
	ID     string `json:"id"`
	Vendor Vendor `json:"vendor"`
}

// Vendor represents a vendor name.
type Vendor struct {
	Name string `json:"name"`
}

// searchResponse wraps the EUVD search API response.
type searchResponse struct {
	Content       []EUVDRecord `json:"content"`
	TotalElements int          `json:"totalElements"`
	TotalPages    int          `json:"totalPages"`
	PageNumber    int          `json:"pageNumber"`
	PageSize      int          `json:"pageSize"`
}

// Manager handles EUVD data fetching and parsing.
type Manager struct {
	config  provider.Config
	client  *http.Client
	baseURL string
}

// NewManager creates a new EUVD manager instance with the default API URL.
func NewManager(config provider.Config) *Manager {
	return NewManagerWithURL(SearchURL, config)
}

// NewManagerWithURL creates a new EUVD manager instance with a custom API URL (for testing).
func NewManagerWithURL(baseURL string, config provider.Config) *Manager {
	return &Manager{
		config:  config,
		baseURL: baseURL,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

// GetAllExploited fetches all exploited vulnerabilities using paginated search.
// Returns records keyed by EUVD ID, the URLs fetched, and any error.
func (m *Manager) GetAllExploited(ctx context.Context) (map[string]map[string]interface{}, []string, error) {
	records := make(map[string]map[string]interface{})
	urls := []string{m.baseURL + "?exploited=true"}
	page := 0

	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		pageURL := fmt.Sprintf("%s?exploited=true&page=%d&size=%d", m.baseURL, page, MaxPageSize)

		resp, err := m.fetchPage(ctx, pageURL)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch page %d: %w", page, err)
		}

		for _, rec := range resp.Content {
			enhanced := m.enhanceRecord(rec)
			records[rec.ID] = enhanced
		}

		m.config.Logger.InfoContext(ctx, "fetched EUVD page",
			"page", page,
			"records_on_page", len(resp.Content),
			"total_records", resp.TotalElements,
			"total_pages", resp.TotalPages,
		)

		page++
		if page >= resp.TotalPages || len(resp.Content) == 0 {
			break
		}

		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(PollInterval):
		}
	}

	return records, urls, nil
}

// fetchPage fetches a single page from the EUVD search API.
func (m *Manager) fetchPage(ctx context.Context, rawURL string) (*searchResponse, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch data: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := vulnzhttp.ReadLimitedBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var searchResp searchResponse
	if err := json.Unmarshal(body, &searchResp); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return &searchResp, nil
}

// enhanceRecord transforms an EUVD API record into an enriched map with EU CRA metadata.
func (m *Manager) enhanceRecord(rec EUVDRecord) map[string]interface{} {
	entry := map[string]interface{}{
		"id":                rec.ID,
		"euvdId":            rec.ID,
		"description":       rec.Description,
		"datePublished":     rec.DatePublished,
		"dateUpdated":       rec.DateUpdated,
		"baseScore":         rec.BaseScore,
		"baseScoreVersion":  rec.BaseScoreVersion,
		"baseScoreVector":   rec.BaseScoreVector,
		"assigner":          rec.Assigner,
		"epss":              rec.EPSS,
		"exploitedSince":    rec.ExploitedSince,
		"exploited_in_wild": true,
		"namespace":         "euvd",
	}

	// Parse references (newline-separated)
	if rec.References != "" {
		entry["references"] = parseNewlineList(rec.References)
	}

	// Parse aliases (newline-separated, e.g., CVE IDs)
	if rec.Aliases != "" {
		entry["aliases"] = parseNewlineList(rec.Aliases)
	}

	// Extract CVE IDs from aliases
	cveIDs := extractCVEIDs(rec.Aliases)
	if len(cveIDs) > 0 {
		entry["cveIds"] = cveIDs
	}

	// Extract affected products
	products := make([]map[string]string, 0, len(rec.EnisaIDProduct))
	for _, p := range rec.EnisaIDProduct {
		products = append(products, map[string]string{
			"name":    p.Product.Name,
			"version": p.ProductVersion,
		})
	}
	entry["affectedProducts"] = products

	// Extract vendors
	vendors := make([]string, 0, len(rec.EnisaIDVendor))
	for _, v := range rec.EnisaIDVendor {
		vendors = append(vendors, v.Vendor.Name)
	}
	entry["vendors"] = vendors

	// EU CRA compliance metadata
	entry["metadata"] = map[string]interface{}{
		"source":                     "euvd-exploited",
		"eu_cra_active_exploitation": true,
		"requires_immediate_action":  true,
		"exploited_since":            rec.ExploitedSince,
	}

	return entry
}

// SaveRaw fetches and saves the raw EUVD exploited data to the workspace.
func (m *Manager) SaveRaw(ctx context.Context) error {
	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return fmt.Errorf("create input directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ExploitedURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch data: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := vulnzhttp.ReadLimitedBody(resp)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	destPath := filepath.Join(inputDir, "euvd-exploited.json")
	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return fmt.Errorf("save data: %w", err)
	}

	return nil
}

func parseNewlineList(s string) []string {
	if s == "" {
		return nil
	}
	result := make([]string, 0)
	for _, line := range splitLines(s) {
		trimmed := trimSpace(line)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func extractCVEIDs(aliases string) []string {
	if aliases == "" {
		return nil
	}
	result := make([]string, 0)
	for _, line := range splitLines(aliases) {
		trimmed := trimSpace(line)
		if len(trimmed) > 4 && trimmed[:4] == "CVE-" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

// GetTotalExploitedCount fetches the total count of exploited vulnerabilities.
func (m *Manager) GetTotalExploitedCount(ctx context.Context) (int, error) {
	pageURL := fmt.Sprintf("%s?exploited=true&page=0&size=1", SearchURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch data: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := vulnzhttp.ReadLimitedBody(resp)
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}

	var searchResp searchResponse
	if err := json.Unmarshal(body, &searchResp); err != nil {
		return 0, fmt.Errorf("parse JSON: %w", err)
	}

	return searchResp.TotalElements, nil
}
