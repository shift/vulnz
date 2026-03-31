package eol

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

type Release struct {
	Name         string `json:"name"`
	Support      string `json:"support,omitempty"`
	EOL          string `json:"eol,omitempty"`
	Latest       string `json:"latest,omitempty"`
	LTS          bool   `json:"lts,omitempty"`
	ReleaseDate  string `json:"releaseDate,omitempty"`
	Discontinued string `json:"discontinued,omitempty"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Product struct {
	Name        string       `json:"name"`
	Identifiers []Identifier `json:"identifiers,omitempty"`
	Releases    []Release    `json:"releases,omitempty"`
}

type APIResponse struct {
	Result []Product `json:"result"`
}

type Manager struct {
	url    string
	config provider.Config
	client *http.Client
}

func NewManager(url string, config provider.Config) *Manager {
	return &Manager{
		url:    url,
		config: config,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

func (m *Manager) URLs() []string {
	return []string{m.url}
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	products, err := m.download(ctx)
	if err != nil {
		return nil, fmt.Errorf("download EOL data: %w", err)
	}

	records, err := m.parse(products)
	if err != nil {
		return nil, fmt.Errorf("parse EOL data: %w", err)
	}

	return records, nil
}

func (m *Manager) download(ctx context.Context) ([]Product, error) {
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
		return nil, fmt.Errorf("fetch EOL data: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := vulnzhttp.ReadLimitedBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	destPath := filepath.Join(inputDir, "eol.json")
	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return nil, fmt.Errorf("save EOL data: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return apiResp.Result, nil
}

func (m *Manager) parse(products []Product) (map[string]map[string]interface{}, error) {
	result := make(map[string]map[string]interface{})

	for _, product := range products {
		if product.Name == "" {
			continue
		}

		for _, release := range product.Releases {
			if release.Name == "" {
				continue
			}

			key := fmt.Sprintf("eol:%s:%s", product.Name, release.Name)

			entry := map[string]interface{}{
				"product":      product.Name,
				"cycle":        release.Name,
				"support":      release.Support,
				"eol":          release.EOL,
				"latest":       release.Latest,
				"lts":          release.LTS,
				"releaseDate":  release.ReleaseDate,
				"discontinued": release.Discontinued,
				"namespace":    "eol",
			}

			if len(product.Identifiers) > 0 {
				idMap := make(map[string]interface{}, len(product.Identifiers))
				for _, id := range product.Identifiers {
					if id.Type != "" && id.Value != "" {
						idMap[id.Type] = id.Value
					}
				}
				if len(idMap) > 0 {
					entry["identifiers"] = idMap
				}
			}

			entry["metadata"] = map[string]interface{}{
				"source":       "endoflife.date",
				"record_type":  "lifecycle",
				"product_name": product.Name,
				"cycle_name":   release.Name,
			}

			result[key] = entry
		}
	}

	return result, nil
}
