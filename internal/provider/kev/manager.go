package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	vulnzhttp "github.com/shift/vulnz/internal/http"
	"github.com/shift/vulnz/internal/provider"
)

// Record represents a single entry from the EUVD consolidated KEV dump.
type Record struct {
	CveID         string   `json:"cveId"`
	EuvdID        string   `json:"euvdId"`
	VendorProject string   `json:"vendorProject,omitempty"`
	Product       string   `json:"product,omitempty"`
	DateAdded     string   `json:"dateAdded"`
	Sources       []string `json:"sources"`
}

// Manager handles KEV data fetching and parsing.
type Manager struct {
	url    string
	config provider.Config
	client *http.Client
}

// NewManager creates a new KEV manager instance.
func NewManager(url string, config provider.Config) *Manager {
	return &Manager{
		url:    url,
		config: config,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

// URLs returns the list of URLs this manager fetches from.
func (m *Manager) URLs() []string {
	return []string{m.url}
}

// Get fetches and parses KEV data from the EUVD consolidated dump,
// returning a map of CVE ID to enhanced record.
func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	records, err := m.download(ctx)
	if err != nil {
		return nil, fmt.Errorf("download KEV catalog: %w", err)
	}

	enhanced, err := m.enhance(records)
	if err != nil {
		return nil, fmt.Errorf("enhance KEV records: %w", err)
	}

	return enhanced, nil
}

// download fetches the EUVD KEV dump and saves it to the workspace.
func (m *Manager) download(ctx context.Context) ([]Record, error) {
	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, fmt.Errorf("create input directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch KEV data: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := vulnzhttp.ReadLimitedBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	destPath := filepath.Join(inputDir, "kev.json")
	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return nil, fmt.Errorf("save KEV data: %w", err)
	}

	var records []Record
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return records, nil
}

// enhance processes KEV records and injects EU CRA compliance metadata.
//
// EU CRA compliance requires strict handling and immediate reporting of actively
// exploited vulnerabilities. This function injects the exploited_in_wild flag
// to enable policy engines to trigger non-deferrable patching SLAs.
// It also enriches records with source attribution (cisa_kev, eukev_kev).
func (m *Manager) enhance(records []Record) (map[string]map[string]interface{}, error) {
	result := make(map[string]map[string]interface{}, len(records))

	for _, rec := range records {
		if rec.CveID == "" {
			continue
		}

		entry := map[string]interface{}{
			"cveId":             rec.CveID,
			"euvdId":            rec.EuvdID,
			"dateAdded":         rec.DateAdded,
			"sources":           rec.Sources,
			"exploited_in_wild": true,
			"namespace":         "euvd:kev",
		}

		if rec.VendorProject != "" {
			entry["vendorProject"] = rec.VendorProject
		}
		if rec.Product != "" {
			entry["product"] = rec.Product
		}

		isEUSource := false
		isCISASource := false
		for _, s := range rec.Sources {
			if s == "eukev_kev" {
				isEUSource = true
			}
			if s == "cisa_kev" {
				isCISASource = true
			}
		}

		entry["metadata"] = map[string]interface{}{
			"source":                     "euvd-kev",
			"eu_cra_active_exploitation": true,
			"requires_immediate_action":  true,
			"kev_date_added":             rec.DateAdded,
			"cisa_kev":                   isCISASource,
			"eu_kev":                     isEUSource,
		}

		result[rec.CveID] = entry
	}

	return result, nil
}
