package bsicertbund

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/shift/vulnz/internal/provider"
)

type indexEntry struct {
	ID       string       `json:"id"`
	Title    string       `json:"title"`
	Content  indexContent `json:"content"`
	Category []struct {
		Scheme string `json:"scheme"`
		Term   string `json:"term"`
	} `json:"category"`
}

type indexContent struct {
	Src string `json:"src"`
}

type csafDocument struct {
	Document        csafDocumentNode    `json:"document"`
	ProductTree     csafProductTree     `json:"product_tree"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
}

type csafDocumentNode struct {
	Title             string                `json:"title"`
	CSAFVersion       string                `json:"csaf_version"`
	Tracking          csafTracking          `json:"tracking"`
	AggregateSeverity csafAggregateSeverity `json:"aggregate_severity"`
	References        []csafReference       `json:"references"`
	Distribution      csafDistribution      `json:"distribution"`
}

type csafTracking struct {
	ID                 string `json:"id"`
	InitialReleaseDate string `json:"initial_release_date"`
	CurrentReleaseDate string `json:"current_release_date"`
}

type csafAggregateSeverity struct {
	Text string `json:"text"`
}

type csafReference struct {
	URL string `json:"url"`
}

type csafDistribution struct {
	TLP csafTLP `json:"tlp"`
}

type csafTLP struct {
	Label string `json:"label"`
}

type csafProductTree struct {
	Branches []csafBranch `json:"branches"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Product  *csafProduct `json:"product,omitempty"`
	Branches []csafBranch `json:"branches,omitempty"`
}

type csafProduct struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
}

type csafVulnerability struct {
	CVE           string            `json:"cve"`
	Scores        []csafScoreEntry  `json:"scores"`
	ProductStatus csafProductStatus `json:"product_status"`
}

type csafScoreEntry struct {
	CVSSv3 *csafCVSSv3 `json:"cvss_v3,omitempty"`
	CVSSv2 *csafCVSSv2 `json:"cvss_v2,omitempty"`
}

type csafCVSSv3 struct {
	BaseScore           float64 `json:"baseScore"`
	VectorString        string  `json:"vectorString"`
	ExploitabilityScore float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64 `json:"impactScore,omitempty"`
}

type csafCVSSv2 struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

type csafProductStatus struct {
	KnownAffected []string `json:"known_affected"`
}

type Manager struct {
	indexURL string
	config   provider.Config
	client   *http.Client
	urls     []string
	urlsMu   sync.Mutex
}

func NewManager(config provider.Config) *Manager {
	return NewManagerWithURL(DefaultIndexURL, config)
}

func NewManagerWithURL(indexURL string, config provider.Config) *Manager {
	return &Manager{
		indexURL: indexURL,
		config:   config,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
		urls: []string{},
	}
}

func (m *Manager) URLs() []string {
	m.urlsMu.Lock()
	defer m.urlsMu.Unlock()
	result := make([]string, len(m.urls))
	copy(result, m.urls)
	return result
}

func (m *Manager) appendURL(u string) {
	m.urlsMu.Lock()
	defer m.urlsMu.Unlock()
	m.urls = append(m.urls, u)
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, fmt.Errorf("create input directory: %w", err)
	}

	entries, err := m.fetchIndex(ctx, inputDir)
	if err != nil {
		return nil, fmt.Errorf("fetch CSAF index: %w", err)
	}

	records := make(map[string]map[string]interface{})

	for i, entry := range entries {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if entry.Content.Src == "" {
			m.config.Logger.WarnContext(ctx, "entry missing CSAF document URL, skipping", "id", entry.ID, "index", i)
			continue
		}

		doc, err := m.fetchDocument(ctx, entry.Content.Src, inputDir)
		if err != nil {
			m.config.Logger.WarnContext(ctx, "failed to fetch CSAF document", "id", entry.ID, "url", entry.Content.Src, "error", err)
			continue
		}

		docRecords := parseCSAF(doc, entry)
		for vulnID, record := range docRecords {
			records[vulnID] = record
		}
	}

	return records, nil
}

func (m *Manager) fetchIndex(ctx context.Context, inputDir string) ([]indexEntry, error) {
	m.appendURL(m.indexURL)
	m.config.Logger.InfoContext(ctx, "fetching BSI CERT-Bund CSAF index")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.indexURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	destPath := filepath.Join(inputDir, "bsi_csaf_index.json")
	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return nil, fmt.Errorf("save index: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse index JSON: %w", err)
	}

	feedRaw, ok := raw["feed"]
	if !ok {
		return nil, fmt.Errorf("index missing 'feed' field")
	}

	var feed struct {
		Entry []indexEntry `json:"entry"`
	}
	if err := json.Unmarshal(feedRaw, &feed); err != nil {
		return nil, fmt.Errorf("parse feed entries: %w", err)
	}

	m.config.Logger.InfoContext(ctx, "found CSAF documents in BSI index", "count", len(feed.Entry))

	return feed.Entry, nil
}

func (m *Manager) fetchDocument(ctx context.Context, docURL string, inputDir string) (*csafDocument, error) {
	m.appendURL(docURL)
	m.config.Logger.InfoContext(ctx, "downloading CSAF document", "url", docURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	filename := filepath.Base(docURL)
	destPath := filepath.Join(inputDir, filename)
	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return nil, fmt.Errorf("save document: %w", err)
	}

	var doc csafDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse CSAF document: %w", err)
	}

	return &doc, nil
}

func parseCSAF(doc *csafDocument, entry indexEntry) map[string]map[string]interface{} {
	records := make(map[string]map[string]interface{})

	document := doc.Document
	tracking := document.Tracking
	advisoryID := tracking.ID
	title := document.Title
	aggregateSeverity := document.AggregateSeverity.Text

	products := traverseProductTree(doc.ProductTree)

	var urls []string
	for _, ref := range document.References {
		if ref.URL != "" {
			urls = append(urls, ref.URL)
		}
	}

	for _, vuln := range doc.Vulnerabilities {
		cveID := vuln.CVE
		vulnID := cveID
		if vulnID == "" {
			vulnID = advisoryID
		}

		var cvssList []map[string]interface{}
		for _, scoreEntry := range vuln.Scores {
			if scoreEntry.CVSSv3 != nil {
				metrics := map[string]interface{}{
					"baseScore": scoreEntry.CVSSv3.BaseScore,
				}
				if scoreEntry.CVSSv3.ExploitabilityScore != 0 {
					metrics["exploitabilityScore"] = scoreEntry.CVSSv3.ExploitabilityScore
				}
				if scoreEntry.CVSSv3.ImpactScore != 0 {
					metrics["impactScore"] = scoreEntry.CVSSv3.ImpactScore
				}
				cvssList = append(cvssList, map[string]interface{}{
					"version": "3.1",
					"vector":  scoreEntry.CVSSv3.VectorString,
					"metrics": metrics,
				})
			} else if scoreEntry.CVSSv2 != nil {
				cvssList = append(cvssList, map[string]interface{}{
					"version": "2.0",
					"vector":  scoreEntry.CVSSv2.VectorString,
					"metrics": map[string]interface{}{
						"baseScore": scoreEntry.CVSSv2.BaseScore,
					},
				})
			}
		}

		var affected []map[string]string
		for _, productID := range vuln.ProductStatus.KnownAffected {
			prod, ok := products[productID]
			if ok && prod != nil {
				affected = append(affected, *prod)
			}
		}

		severity := germanSeverityMap(aggregateSeverity)

		tlp := "WHITE"
		if document.Distribution.TLP.Label != "" {
			tlp = document.Distribution.TLP.Label
		}

		advisoryLink := fmt.Sprintf("https://wid.cert-bund.de/portal/wid/securityadvisory?name=%s", strings.ReplaceAll(advisoryID, "-W-", "-"))

		record := map[string]interface{}{
			"id":          vulnID,
			"namespace":   "bsi:cert-bund",
			"description": title,
			"severity":    severity,
			"cvss":        cvssList,
			"urls":        urls,
			"fix": map[string]interface{}{
				"state":    "unknown",
				"versions": []interface{}{},
			},
			"advisories": []map[string]string{
				{
					"id":   advisoryID,
					"link": advisoryLink,
				},
			},
			"affected": affected,
			"metadata": map[string]interface{}{
				"source":                 "bsi-cert-bund",
				"bsi_tr_03116_compliant": true,
				"sovereign_database":     true,
				"advisory_id":            advisoryID,
				"cve_id":                 cveID,
				"aggregate_severity_de":  aggregateSeverity,
				"published":              tracking.InitialReleaseDate,
				"updated":                tracking.CurrentReleaseDate,
				"csaf_version":           document.CSAFVersion,
				"tlp":                    tlp,
			},
		}

		records[vulnID] = record
	}

	return records
}

func traverseProductTree(tree csafProductTree) map[string]*map[string]string {
	products := make(map[string]*map[string]string)
	walkBranches(tree.Branches, "", products)
	return products
}

func walkBranches(branches []csafBranch, vendor string, products map[string]*map[string]string) {
	for _, branch := range branches {
		currentVendor := vendor
		if branch.Category == "vendor" {
			currentVendor = branch.Name
		}

		if branch.Product != nil {
			version := "*"
			name := branch.Product.Name
			if strings.Contains(name, "<") {
				parts := strings.SplitN(name, "<", 2)
				version = strings.TrimSpace(parts[1])
			} else if strings.Contains(name, "=") {
				parts := strings.SplitN(name, "=", 2)
				version = strings.TrimSpace(parts[1])
			}

			displayName := branch.Name
			if branch.Category == "product_name" {
				displayName = branch.Name
			} else {
				tokens := strings.Fields(branch.Product.Name)
				if len(tokens) > 0 {
					displayName = tokens[0]
				}
			}

			prod := map[string]string{
				"name":    displayName,
				"vendor":  currentVendor,
				"version": version,
			}
			products[branch.Product.ProductID] = &prod
		}

		if len(branch.Branches) > 0 {
			walkBranches(branch.Branches, currentVendor, products)
		}
	}
}

func germanSeverityMap(severity string) string {
	switch strings.ToLower(severity) {
	case "kritisch":
		return "Critical"
	case "hoch":
		return "High"
	case "mittel":
		return "Medium"
	case "niedrig":
		return "Low"
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Unknown"
	}
}
