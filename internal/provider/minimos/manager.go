package minimos

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

type secDB struct {
	Packages []pkgEntry `json:"packages"`
}

type pkgEntry struct {
	Pkg pkgInfo `json:"pkg"`
}

type pkgInfo struct {
	Name     string              `json:"name"`
	SecFixes map[string][]string `json:"secfixes"`
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
	db, err := m.download(ctx)
	if err != nil {
		return nil, fmt.Errorf("download minimos security db: %w", err)
	}

	records, err := m.parse(db)
	if err != nil {
		return nil, fmt.Errorf("parse minimos security db: %w", err)
	}

	return records, nil
}

func (m *Manager) download(ctx context.Context) (*secDB, error) {
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
		return nil, fmt.Errorf("fetch minimos security data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	destPath := filepath.Join(inputDir, "security.json")
	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return nil, fmt.Errorf("save minimos security data: %w", err)
	}

	var db secDB
	if err := json.Unmarshal(body, &db); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return &db, nil
}

func (m *Manager) parse(db *secDB) (map[string]map[string]interface{}, error) {
	result := make(map[string]map[string]interface{})

	for _, entry := range db.Packages {
		pkgName := entry.Pkg.Name

		for fixVersion, vulnIDs := range entry.Pkg.SecFixes {
			for _, rawID := range vulnIDs {
				vid := strings.TrimSpace(rawID)
				if vid == "" {
					continue
				}

				if _, exists := result[vid]; !exists {
					result[vid] = map[string]interface{}{
						"Vulnerability": map[string]interface{}{
							"Name":          vid,
							"NamespaceName": Namespace,
							"Link":          fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vid),
							"Severity":      "Unknown",
							"FixedIn":       []interface{}{},
						},
					}
				}

				vulnMap := result[vid]["Vulnerability"].(map[string]interface{})
				fixedInList := vulnMap["FixedIn"].([]interface{})

				fixedInList = append(fixedInList, map[string]interface{}{
					"Name":          pkgName,
					"Version":       fixVersion,
					"VersionFormat": "apk",
					"NamespaceName": Namespace,
				})
				vulnMap["FixedIn"] = fixedInList
			}
		}
	}

	return result, nil
}
