package csatics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/shift/vulnz/internal/provider"
)

type gitHubDirEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Type        string `json:"type"`
	DownloadURL string `json:"download_url"`
}

type csafDocument struct {
	Document        csafDocumentNode    `json:"document"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
	ProductTree     csafProductTree     `json:"product_tree"`
}

type csafDocumentNode struct {
	Tracking csafTracking `json:"tracking"`
	Title    string       `json:"title"`
	Notes    []csafNote   `json:"notes"`
}

type csafTracking struct {
	ID                 string `json:"id"`
	InitialReleaseDate string `json:"initial_release_date"`
	CurrentReleaseDate string `json:"current_release_date"`
}

type csafNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
}

type csafVulnerability struct {
	CVE    string           `json:"cve"`
	Scores []csafScoreEntry `json:"scores"`
}

type csafScoreEntry struct {
	Cvss csafCvss `json:"cvss"`
}

type csafCvss struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

type csafProductTree struct {
	Relationships []csafRelationship `json:"relationships"`
}

type csafRelationship struct {
	Product csafProductRef `json:"product"`
}

type csafProductRef struct {
	Name                        string              `json:"name"`
	ProductIdentificationHelper csafProductIDHelper `json:"product_identification_helper"`
}

type csafProductIDHelper struct {
	CPEs []string `json:"cpes"`
}

type Manager struct {
	baseURL     string
	config      provider.Config
	httpClient  *http.Client
	fetchedURLs []string
}

func NewManager(url string, config provider.Config) *Manager {
	return &Manager{
		baseURL:     url,
		config:      config,
		fetchedURLs: []string{},
		httpClient: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

func NewManagerWithURL(url string, config provider.Config, client *http.Client) *Manager {
	return &Manager{
		baseURL:     url,
		config:      config,
		fetchedURLs: []string{},
		httpClient:  client,
	}
}

func (m *Manager) URLs() []string {
	return m.fetchedURLs
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	advisories, err := m.downloadAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("download all advisories: %w", err)
	}

	return m.parse(advisories), nil
}

func (m *Manager) listCategories(ctx context.Context) ([]gitHubDirEntry, error) {
	return m.listDir(ctx, m.baseURL)
}

func (m *Manager) listYears(ctx context.Context, category string) ([]gitHubDirEntry, error) {
	url := fmt.Sprintf("%s/%s", m.baseURL, category)
	return m.listDir(ctx, url)
}

func (m *Manager) listFiles(ctx context.Context, category, year string) ([]gitHubDirEntry, error) {
	url := fmt.Sprintf("%s/%s/%s", m.baseURL, category, year)
	return m.listDir(ctx, url)
}

func (m *Manager) listDir(ctx context.Context, url string) ([]gitHubDirEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", url, err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch directory listing from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", url, err)
	}

	var entries []gitHubDirEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse JSON from %s: %w", url, err)
	}

	return entries, nil
}

func (m *Manager) fetchCSAF(ctx context.Context, downloadURL string) (*csafDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CSAF from %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, downloadURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read CSAF from %s: %w", downloadURL, err)
	}

	var doc csafDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse CSAF JSON from %s: %w", downloadURL, err)
	}

	return &doc, nil
}

func (m *Manager) downloadAll(ctx context.Context) ([]*csafDocument, error) {
	categories, err := m.listCategories(ctx)
	if err != nil {
		return nil, fmt.Errorf("list categories: %w", err)
	}

	var allAdvisories []*csafDocument

	for _, cat := range categories {
		if cat.Type != "dir" {
			continue
		}

		years, err := m.listYears(ctx, cat.Name)
		if err != nil {
			continue
		}

		for _, yr := range years {
			if yr.Type != "dir" {
				continue
			}

			files, err := m.listFiles(ctx, cat.Name, yr.Name)
			if err != nil {
				continue
			}

			for _, f := range files {
				if f.Type != "file" || !strings.HasSuffix(f.Name, ".json") {
					continue
				}

				if f.DownloadURL == "" {
					continue
				}

				m.fetchedURLs = append(m.fetchedURLs, f.DownloadURL)

				doc, err := m.fetchCSAF(ctx, f.DownloadURL)
				if err != nil {
					continue
				}

				allAdvisories = append(allAdvisories, doc)
			}
		}
	}

	return allAdvisories, nil
}

func (m *Manager) parse(advisories []*csafDocument) map[string]map[string]interface{} {
	result := make(map[string]map[string]interface{})

	for _, advisory := range advisories {
		if advisory == nil {
			continue
		}

		advisoryID := advisory.Document.Tracking.ID
		title := advisory.Document.Title
		published := advisory.Document.Tracking.InitialReleaseDate
		updated := advisory.Document.Tracking.CurrentReleaseDate

		description := ""
		for _, note := range advisory.Document.Notes {
			if note.Category == "summary" {
				description = note.Text
				break
			}
		}

		var cves []string
		for _, vuln := range advisory.Vulnerabilities {
			if vuln.CVE != "" {
				cves = append(cves, vuln.CVE)
			}
		}

		vendor, product, cpes := extractProducts(advisory)

		otCategory := ClassifyOT(title + " " + description)

		advisoryLink := ""
		if advisoryID != "" {
			advisoryLink = fmt.Sprintf("https://www.cisa.gov/news-events/ics-advisories/%s", strings.ToLower(advisoryID))
		}

		if len(cves) == 0 {
			record := buildRecord(advisoryID, advisoryID, description, title, published, updated, vendor, product, cpes, otCategory, advisoryLink, advisory.Vulnerabilities)
			result[advisoryID] = record
			continue
		}

		for _, cveID := range cves {
			record := buildRecord(cveID, advisoryID, description, title, published, updated, vendor, product, cpes, otCategory, advisoryLink, advisory.Vulnerabilities)
			result[cveID] = record
		}
	}

	return result
}

func extractProducts(advisory *csafDocument) (string, string, []string) {
	vendor := ""
	product := ""
	var cpes []string

	for _, rel := range advisory.ProductTree.Relationships {
		fullName := rel.Product.Name
		if fullName != "" && vendor == "" {
			parts := strings.Fields(fullName)
			if len(parts) > 0 {
				vendor = parts[0]
			}
		}
		if fullName != "" {
			product = fullName
		}

		for _, cpe := range rel.Product.ProductIdentificationHelper.CPEs {
			if cpe != "" {
				cpes = append(cpes, cpe)
			}
		}
	}

	return vendor, product, cpes
}

func buildRecord(vulnID, advisoryID, description, title, published, updated, vendor, product string, cpes []string, otCategory, advisoryLink string, vulnerabilities []csafVulnerability) map[string]interface{} {
	cvssData := map[string]interface{}{}
	for _, vuln := range vulnerabilities {
		if vuln.CVE == vulnID {
			for _, score := range vuln.Scores {
				cvssData = map[string]interface{}{
					"baseScore":    score.Cvss.BaseScore,
					"vectorString": score.Cvss.VectorString,
				}
				break
			}
			break
		}
	}

	cvss := []map[string]interface{}{}
	baseScore, _ := cvssData["baseScore"].(float64)
	vectorStr, _ := cvssData["vectorString"].(string)
	if baseScore > 0 || vectorStr != "" {
		cvss = append(cvss, map[string]interface{}{
			"version": detectCVSSVersion(vectorStr),
			"vector":  vectorStr,
			"metrics": map[string]interface{}{
				"baseScore": baseScore,
			},
		})
	}

	advisories := []map[string]interface{}{}
	if advisoryID != "" {
		advisories = append(advisories, map[string]interface{}{
			"id":   advisoryID,
			"link": advisoryLink,
		})
	}

	recordCVEs := []string{}
	if strings.HasPrefix(vulnID, "CVE-") {
		recordCVEs = append(recordCVEs, vulnID)
	}

	icsOTMetadata := map[string]interface{}{
		"facility_sectors": nil,
		"ot_category":      otCategory,
		"cpes":             cpes,
	}
	if len(cpes) == 0 {
		icsOTMetadata["cpes"] = nil
	}

	record := map[string]interface{}{
		"id":          vulnID,
		"namespace":   "cisa:ics-cert",
		"description": description,
		"cvss":        cvss,
		"fix": map[string]interface{}{
			"state":    "unknown",
			"versions": []interface{}{},
		},
		"advisories": advisories,
		"metadata": map[string]interface{}{
			"cisa_advisory_id":  advisoryID,
			"cisa_title":        title,
			"published":         published,
			"updated":           updated,
			"cves":              recordCVEs,
			"vendor":            vendor,
			"product":           product,
			"affected_versions": nil,
			"sectors_critical":  nil,
			"system_type":       nil,
			"source":            "cisa-ics-cert",
			"ics_ot_metadata":   icsOTMetadata,
		},
	}

	return record
}

func detectCVSSVersion(vector string) string {
	if strings.HasPrefix(vector, "CVSS:3.1") {
		return "3.1"
	}
	if strings.HasPrefix(vector, "CVSS:3.0") {
		return "3.0"
	}
	if strings.HasPrefix(vector, "CVSS:2.0") || strings.Contains(vector, "AV:") {
		return "2.0"
	}
	return "3.1"
}

func ClassifyOT(text string) string {
	lower := strings.ToLower(text)

	plcTerms := []string{"plc", "programmable logic controller"}
	for _, term := range plcTerms {
		if strings.Contains(lower, term) {
			return "plc"
		}
	}

	scadaTerms := []string{"scada", "supervisory control"}
	for _, term := range scadaTerms {
		if strings.Contains(lower, term) {
			return "scada"
		}
	}

	hmiTerms := []string{"hmi", "human machine interface"}
	for _, term := range hmiTerms {
		if strings.Contains(lower, term) {
			return "hmi"
		}
	}

	rtuTerms := []string{"rtu", "remote terminal unit"}
	for _, term := range rtuTerms {
		if strings.Contains(lower, term) {
			return "rtu"
		}
	}

	dcsTerms := []string{"dcs", "distributed control"}
	for _, term := range dcsTerms {
		if strings.Contains(lower, term) {
			return "dcs"
		}
	}

	iotTerms := []string{"iot", "internet of things", "embedded"}
	for _, term := range iotTerms {
		if strings.Contains(lower, term) {
			return "iot"
		}
	}

	firmwareTerms := []string{"firmware", "embedded system"}
	for _, term := range firmwareTerms {
		if strings.Contains(lower, term) {
			return "firmware"
		}
	}

	return "ics-generic"
}
