package euvdmapping

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/shift/vulnz/internal/provider"
)

// Mapping represents a single CVE-to-EUVD ID mapping.
type Mapping struct {
	EuvdID string `json:"euvd_id"`
	CveID  string `json:"cve_id"`
}

// Manager handles CVE-EUVD mapping data fetching and parsing.
type Manager struct {
	url    string
	config provider.Config
	client *http.Client
}

// NewManager creates a new EUVD mapping manager instance.
func NewManager(url string, config provider.Config) *Manager {
	return &Manager{
		url:    url,
		config: config,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

// NewManagerWithURL creates a new EUVD mapping manager with a custom URL (for testing).
func NewManagerWithURL(url string, config provider.Config) *Manager {
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

// Get fetches and parses the CVE-EUVD mapping CSV.
// Returns a slice of Mapping structs.
func (m *Manager) Get(ctx context.Context) ([]Mapping, error) {
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
		return nil, fmt.Errorf("fetch mapping: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read the full response body for saving to workspace
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Save raw CSV to workspace
	destPath := filepath.Join(inputDir, "cve-euvd-mapping.csv")
	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return nil, fmt.Errorf("save mapping: %w", err)
	}

	// Parse CSV
	mappings, err := parseCSV(body)
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}

	return mappings, nil
}

// parseCSV parses the CVE-EUVD mapping CSV data.
// Expected format: euvd_id,cve_id (header row followed by data)
func parseCSV(data []byte) ([]Mapping, error) {
	reader := csv.NewReader(io.NopCloser(io.LimitReader(nil, 0)))
	// Reset reader with actual data
	reader = csv.NewReader(newBytesReader(data))

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read CSV header: %w", err)
	}

	// Validate header
	if len(header) < 2 {
		return nil, fmt.Errorf("invalid CSV header: expected 2 columns, got %d", len(header))
	}

	var mappings []Mapping
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			if _, ok := err.(*csv.ParseError); ok {
				continue
			}
			return nil, fmt.Errorf("read CSV record: %w", err)
		}

		if len(record) < 2 {
			continue
		}

		mappings = append(mappings, Mapping{
			EuvdID: record[0],
			CveID:  record[1],
		})
	}

	return mappings, nil
}

// bytesReader wraps []byte to implement io.Reader.
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
