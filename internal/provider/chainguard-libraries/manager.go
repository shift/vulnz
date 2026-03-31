package chainguardlibraries

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/shift/vulnz/internal/provider"
)

type purlInfo struct {
	Type    string
	Name    string
	Version string
}

type indexResponse struct {
	Entries []indexEntry `json:"entries"`
	Version int          `json:"version"`
}

type indexEntry struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

type openvexVulnerability struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
}

type openvexProductIdentifiers struct {
	PURL string `json:"purl"`
}

type openvexProduct struct {
	Identifiers openvexProductIdentifiers `json:"identifiers"`
}

type openvexStatement struct {
	Vulnerability openvexVulnerability `json:"vulnerability"`
	Products      []openvexProduct     `json:"products"`
	Status        string               `json:"status"`
	Timestamp     string               `json:"timestamp,omitempty"`
	LastUpdated   string               `json:"last_updated,omitempty"`
}

type openvexDocument struct {
	Context     string             `json:"@context"`
	ID          string             `json:"@id"`
	Author      string             `json:"author"`
	Version     int                `json:"version"`
	Supplier    string             `json:"supplier"`
	Timestamp   string             `json:"timestamp"`
	LastUpdated string             `json:"last_updated"`
	Statements  []openvexStatement `json:"statements"`
}

type Manager struct {
	indexURL    string
	config      provider.Config
	client      *http.Client
	fetchedURLs []string
}

func NewManager(indexURL string, config provider.Config) *Manager {
	return &Manager{
		indexURL: indexURL,
		config:   config,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
		fetchedURLs: []string{},
	}
}

func (m *Manager) URLs() []string {
	return m.fetchedURLs
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	entries, err := m.fetchIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch index: %w", err)
	}

	m.fetchedURLs = append(m.fetchedURLs, m.indexURL)

	result := make(map[string]map[string]interface{})

	baseURL := strings.TrimSuffix(m.indexURL, "/all.json")

	for _, entry := range entries {
		docURL := baseURL + "/" + entry.ID
		doc, err := m.fetchDocument(ctx, docURL)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}

		records := m.parseDocument(doc)
		for vulnID, record := range records {
			result[vulnID] = record
		}
	}

	return result, nil
}

func (m *Manager) fetchIndex(ctx context.Context) ([]indexEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.indexURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create index request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

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
		return nil, fmt.Errorf("read index response: %w", err)
	}

	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, fmt.Errorf("create input directory: %w", err)
	}

	destPath := filepath.Join(inputDir, "all.json")
	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return nil, fmt.Errorf("save index: %w", err)
	}

	var indexResp indexResponse
	if err := json.Unmarshal(body, &indexResp); err != nil {
		return nil, fmt.Errorf("parse index JSON: %w", err)
	}

	return indexResp.Entries, nil
}

func (m *Manager) fetchDocument(ctx context.Context, docURL string) (*openvexDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create document request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

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
		return nil, fmt.Errorf("read document response: %w", err)
	}

	m.fetchedURLs = append(m.fetchedURLs, docURL)

	var doc openvexDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse document JSON: %w", err)
	}

	return &doc, nil
}

func ParsePURL(purl string) (*purlInfo, error) {
	if !strings.HasPrefix(purl, "pkg:") {
		return nil, fmt.Errorf("invalid purl: missing pkg: prefix")
	}

	parts := strings.TrimPrefix(purl, "pkg:")
	typeEnd := strings.Index(parts, "/")
	if typeEnd < 0 {
		return nil, fmt.Errorf("invalid purl: missing type separator")
	}

	purlType := parts[:typeEnd]
	rest := parts[typeEnd+1:]

	atIdx := strings.LastIndex(rest, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("invalid purl: missing version")
	}

	name := rest[:atIdx]
	version := rest[atIdx+1:]

	if name == "" || version == "" {
		return nil, fmt.Errorf("invalid purl: empty name or version")
	}

	return &purlInfo{
		Type:    purlType,
		Name:    name,
		Version: version,
	}, nil
}

func filterEcosystem(purl string) bool {
	return strings.HasPrefix(purl, "pkg:pypi/")
}

func (m *Manager) parseDocument(doc *openvexDocument) map[string]map[string]interface{} {
	records := make(map[string]map[string]interface{})

	for _, stmt := range doc.Statements {
		if strings.EqualFold(stmt.Status, "not_affected") {
			continue
		}

		if stmt.Vulnerability.Name == "" {
			continue
		}

		if len(stmt.Products) == 0 {
			continue
		}

		purl := stmt.Products[0].Identifiers.PURL
		if !filterEcosystem(purl) {
			continue
		}

		purlInfo, err := ParsePURL(purl)
		if err != nil {
			continue
		}

		fixedIn := []map[string]interface{}{
			{
				"name":          purlInfo.Name,
				"version":       purlInfo.Version,
				"versionFormat": "pypi",
			},
		}

		description := strings.Join(stmt.Vulnerability.Aliases, ", ")
		if description == "" {
			description = stmt.Vulnerability.Name
		}

		record := map[string]interface{}{
			"name":        stmt.Vulnerability.Name,
			"namespace":   "chainguard-libraries:pypi",
			"severity":    "Unknown",
			"fixedIn":     fixedIn,
			"link":        doc.ID,
			"description": description,
		}

		records[stmt.Vulnerability.Name] = record
	}

	return records
}
