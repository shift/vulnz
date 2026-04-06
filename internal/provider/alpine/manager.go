package alpine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/shift/vulnz/internal/provider"
	"gopkg.in/yaml.v3"
)

type secDB struct {
	Packages []pkgEntry `yaml:"packages"`
}

type pkgEntry struct {
	Pkg pkgInfo `yaml:"pkg"`
}

type pkgInfo struct {
	Name     string              `yaml:"name"`
	SecFixes map[string][]string `yaml:"secfixes"`
}

type Manager struct {
	baseURL string
	config  provider.Config
	client  *http.Client
	urls    []string
}

func NewManager(url string, config provider.Config) *Manager {
	return &Manager{
		baseURL: url,
		config:  config,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

func (m *Manager) URLs() []string {
	return m.urls
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]map[string]interface{}, error) {
	m.urls = nil

	releases, err := m.discoverReleases(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover releases: %w", err)
	}

	if len(releases) == 0 {
		return nil, fmt.Errorf("no releases found")
	}

	result := make(map[string]map[string]map[string]interface{})

	for _, release := range releases {
		records, err := m.fetchRelease(ctx, release)
		if err != nil {
			return nil, fmt.Errorf("fetch release %s: %w", release, err)
		}

		result[release] = records
	}

	return result, nil
}

var (
	releaseLinkRegex = regexp.MustCompile(`^v\d+\.\d+`)
	ignoreLinks      = map[string]bool{"last-update": true, "license.txt": true}
)

func (m *Manager) discoverReleases(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch landing page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, fmt.Errorf("create input directory: %w", err)
	}

	destPath := filepath.Join(inputDir, "index.html")
	tmpPath := destPath + ".tmp"

	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}

	var buf strings.Builder
	tee := io.TeeReader(resp.Body, &buf)
	if _, err := io.Copy(f, tee); err != nil {
		f.Close()
		return nil, fmt.Errorf("stream landing page: %w", err)
	}
	f.Close()

	os.Rename(tmpPath, destPath)

	links := extractLinks(buf.String())

	var releases []string
	for _, link := range links {
		if ignoreLinks[link] {
			continue
		}
		trimmed := strings.TrimRight(link, "/")
		if releaseLinkRegex.MatchString(trimmed) {
			releases = append(releases, trimmed)
		}
	}

	return releases, nil
}

func extractLinks(html string) []string {
	var links []string
	hrefPattern := regexp.MustCompile(`<a\s+[^>]*href\s*=\s*"([^"]*)"`)
	matches := hrefPattern.FindAllStringSubmatch(html, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		href := match[1]
		if !seen[href] {
			seen[href] = true
			links = append(links, href)
		}
	}

	return links
}

func (m *Manager) fetchRelease(ctx context.Context, release string) (map[string]map[string]interface{}, error) {
	dbTypes := []string{"main", "community"}

	var allEntries []pkgEntry

	for _, dbType := range dbTypes {
		if dbType == "community" && release == "v3.2" {
			continue
		}

		db, err := m.fetchYAML(ctx, release, dbType)
		if err != nil {
			return nil, fmt.Errorf("fetch %s/%s: %w", release, dbType, err)
		}

		allEntries = append(allEntries, db.Packages...)
	}

	namespace := fmt.Sprintf("alpine:%s", release)
	return m.parseSecDB(allEntries, namespace), nil
}

func (m *Manager) fetchYAML(ctx context.Context, release, dbType string) (*secDB, error) {
	url := fmt.Sprintf("%s/%s/%s.yaml", m.baseURL, release, dbType)
	m.urls = append(m.urls, url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch yaml: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d for %s", resp.StatusCode, url)
	}

	inputDir := filepath.Join(m.config.Workspace, "input", release)
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, fmt.Errorf("create input directory: %w", err)
	}

	destPath := filepath.Join(inputDir, fmt.Sprintf("%s.yaml", dbType))
	tmpPath := destPath + ".tmp"

	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}

	// Decode YAML from the tee'd stream — one copy to file, one decode pass
	var db secDB
	decoder := yaml.NewDecoder(io.TeeReader(resp.Body, f))
	if err := decoder.Decode(&db); err != nil {
		f.Close()
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	f.Close()

	os.Rename(tmpPath, destPath)

	return &db, nil
}

func (m *Manager) parseSecDB(entries []pkgEntry, namespace string) map[string]map[string]interface{} {
	result := make(map[string]map[string]interface{})

	for _, entry := range entries {
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
							"NamespaceName": namespace,
							"Link":          fmt.Sprintf("%s/%s", SecurityReferenceURL, vid),
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
					"NamespaceName": namespace,
				})
				vulnMap["FixedIn"] = fixedInList
			}
		}
	}

	return result
}
