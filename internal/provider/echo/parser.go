package echo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/shift/vulnz/internal/utils/vulnerability"
)

// Parser fetches and parses Echo test data.
type Parser struct {
	url            string
	namespace      string
	httpClient     *http.Client
	advisoriesDir  string
	advisoriesFile string
}

// NewParser creates a new Echo data parser.
func NewParser(url, namespace, workspaceInput string, httpClient *http.Client) *Parser {
	return &Parser{
		url:            url,
		namespace:      namespace,
		httpClient:     httpClient,
		advisoriesDir:  filepath.Join(workspaceInput, "echo-advisories"),
		advisoriesFile: "data.json",
	}
}

// RawData represents the raw JSON structure from the Echo feed.
// Format: {"package_name": {"CVE-ID": {"severity": "...", "fixed_version": "..."}}}
type RawData map[string]map[string]CVEInfo

// CVEInfo represents vulnerability information for a single CVE.
type CVEInfo struct {
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixed_version"`
}

// Get fetches and parses Echo data, returning a map of vulnerability records.
func (p *Parser) Get(ctx context.Context) (map[string]vulnerability.Vulnerability, error) {
	// Download the data
	if err := p.download(ctx); err != nil {
		return nil, fmt.Errorf("download echo data: %w", err)
	}

	// Load the JSON file
	dataPath := filepath.Join(p.advisoriesDir, p.advisoriesFile)
	rawData, err := p.loadJSON(dataPath)
	if err != nil {
		return nil, fmt.Errorf("load json: %w", err)
	}

	// Normalize to vulnerability records
	vulns := p.normalize(rawData)
	return vulns, nil
}

// download fetches the Echo data from the configured URL.
func (p *Parser) download(ctx context.Context) error {
	// Create advisories directory
	if err := os.MkdirAll(p.advisoriesDir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", p.url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Execute request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Write response to file
	filePath := filepath.Join(p.advisoriesDir, p.advisoriesFile)
	outFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, resp.Body); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// loadJSON reads and parses the JSON data file.
func (p *Parser) loadJSON(path string) (RawData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var rawData RawData
	if err := json.Unmarshal(data, &rawData); err != nil {
		return nil, fmt.Errorf("unmarshal json: %w", err)
	}

	return rawData, nil
}

// normalize transforms raw Echo data into vulnerability records.
func (p *Parser) normalize(rawData RawData) map[string]vulnerability.Vulnerability {
	vulnMap := make(map[string]vulnerability.Vulnerability)
	release := "rolling"
	namespace := fmt.Sprintf("%s:%s", p.namespace, release)

	// Iterate through packages and their CVEs
	for packageName, cves := range rawData {
		for cveID, cveInfo := range cves {
			// Get or create vulnerability record
			vuln, exists := vulnMap[cveID]
			if !exists {
				// Create new vulnerability record
				vuln = vulnerability.Vulnerability{
					Name:          cveID,
					NamespaceName: namespace,
					Severity:      normalizeSeverity(cveInfo.Severity),
					Link:          buildReferenceLink(cveID),
					Description:   "",
					FixedIn:       []vulnerability.FixedIn{},
					CVSS:          []vulnerability.CVSS{},
					Metadata:      make(map[string]any),
				}
			}

			// Add fix information for this package
			fixedIn := vulnerability.FixedIn{
				Name:          packageName,
				NamespaceName: namespace,
				VersionFormat: "dpkg",
				Version:       cveInfo.FixedVersion,
			}

			vuln.FixedIn = append(vuln.FixedIn, fixedIn)
			vulnMap[cveID] = vuln
		}
	}

	return vulnMap
}

// normalizeSeverity ensures severity values are standardized.
func normalizeSeverity(severity string) string {
	if severity == "" {
		return "Unknown"
	}
	return severity
}

// buildReferenceLink creates a reference URL for a CVE ID.
func buildReferenceLink(cveID string) string {
	if len(cveID) > 3 && cveID[:3] == "CVE" {
		return fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)
	}
	return ""
}
