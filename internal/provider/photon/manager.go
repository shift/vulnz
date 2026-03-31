package photon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/shift/vulnz/internal/provider"
)

var (
	advisoryIDRe   = regexp.MustCompile(`Advisory\s+(?:Id|ID)\s*:\s*(PHSA-\d{4}-(?:\d+\.\d+-)?0*\d+)`)
	issueDateRe    = regexp.MustCompile(`(?:Issue\s+date|Issued\s+on)\s*:\s*(\d{4}-\d{2}-\d{2})`)
	advisoryFileRe = regexp.MustCompile(`Security-Updates?-(\d+\.\d+)-(\d+)\.md`)
	cveIDRe        = regexp.MustCompile(`CVE-\d{4}-\d+`)
)

type advisoryInfo struct {
	AdvisoryID string
	Date       string
	URL        string
}

type cveEntry struct {
	CveID         string `json:"cve_id"`
	Pkg           string `json:"pkg"`
	Version       string `json:"version"`
	Release       string `json:"release"`
	PhotonVersion string `json:"photon_version"`
	Advisory      string `json:"advisory"`
}

type Manager struct {
	config              provider.Config
	versions            []string
	wikiURL             string
	client              *http.Client
	urls                []string
	advisoryMap         map[advisoryKey]advisoryInfo
	exportedAdvisoryMap map[string]advisoryInfo
}

type advisoryKey struct {
	version string
	cveID   string
}

func NewManager(config provider.Config) *Manager {
	return NewManagerWithVersions(config, defaultVersions)
}

func NewManagerWithVersions(config provider.Config, versions []string) *Manager {
	return &Manager{
		config:   config,
		versions: versions,
		wikiURL:  DefaultWikiURL,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

func (m *Manager) URLs() []string {
	return m.urls
}

func (m *Manager) SetAdvisoryMap(am map[string]advisoryInfo) {
	m.exportedAdvisoryMap = am
}

func (m *Manager) ParseAdvisoryMap(wikiPath string) map[string]advisoryInfo {
	internal := m.parseAdvisoryMap(wikiPath)
	exported := make(map[string]advisoryInfo, len(internal))
	for k, v := range internal {
		exported[k.version+":"+k.cveID] = v
	}
	return exported
}

func (m *Manager) MergeRecordsFromJSON(data []byte, photonVersion string) (map[string]map[string]interface{}, error) {
	if m.exportedAdvisoryMap != nil {
		m.advisoryMap = make(map[advisoryKey]advisoryInfo, len(m.exportedAdvisoryMap))
		for k, v := range m.exportedAdvisoryMap {
			parts := strings.SplitN(k, ":", 2)
			if len(parts) == 2 {
				m.advisoryMap[advisoryKey{version: parts[0], cveID: parts[1]}] = v
			}
		}
	}

	entries, err := m.parseCVEJSON(data)
	if err != nil {
		return nil, err
	}
	return m.mergeRecords(entries, photonVersion)
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, fmt.Errorf("create input directory: %w", err)
	}

	wikiDir := filepath.Join(inputDir, "photon.wiki")
	if err := m.cloneWiki(ctx, wikiDir); err != nil {
		return nil, fmt.Errorf("clone wiki: %w", err)
	}

	m.advisoryMap = m.parseAdvisoryMap(wikiDir)
	m.config.Logger.Info("parsed advisory mappings from wiki", "count", len(m.advisoryMap))

	m.urls = []string{m.wikiURL}

	result := make(map[string]map[string]interface{})

	for _, version := range m.versions {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		cveURL := CVEURLBase + fmt.Sprintf(CVEFilename, version)
		m.urls = append(m.urls, cveURL)

		entries, err := m.fetchCVEData(ctx, cveURL, version, inputDir)
		if err != nil {
			m.config.Logger.WarnContext(ctx, "failed to fetch CVE data, skipping version", "version", version, "url", cveURL, "error", err)
			continue
		}

		records, err := m.mergeRecords(entries, version)
		if err != nil {
			return nil, fmt.Errorf("merge records for photon %s: %w", version, err)
		}

		for id, record := range records {
			result[id] = record
		}
	}

	return result, nil
}

func (m *Manager) cloneWiki(ctx context.Context, destDir string) error {
	if _, err := os.Stat(destDir); err == nil {
		return nil
	}

	parentDir := filepath.Dir(destDir)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	_, err := git.PlainCloneContext(ctx, destDir, false, &git.CloneOptions{
		URL:          m.wikiURL,
		SingleBranch: true,
		Depth:        1,
	})
	if err != nil {
		return fmt.Errorf("git clone wiki: %w", err)
	}

	return nil
}

func (m *Manager) fetchCVEData(ctx context.Context, url, version, inputDir string) ([]cveEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CVE data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("empty response body from %s", url)
	}

	filename := fmt.Sprintf(CVEFilename, version)
	destPath := filepath.Join(inputDir, filename)
	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return nil, fmt.Errorf("save CVE data: %w", err)
	}

	return m.parseCVEJSON(body)
}

func (m *Manager) parseCVEJSON(data []byte) ([]cveEntry, error) {
	var entries []cveEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse CVE JSON: %w", err)
	}
	return entries, nil
}

func (m *Manager) parseAdvisoryMap(wikiPath string) map[advisoryKey]advisoryInfo {
	result := make(map[advisoryKey]advisoryInfo)

	if _, err := os.Stat(wikiPath); os.IsNotExist(err) {
		return result
	}

	entries, err := os.ReadDir(wikiPath)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}

		filenameMatch := advisoryFileRe.FindStringSubmatch(entry.Name())
		if filenameMatch == nil {
			continue
		}

		version := filenameMatch[1]
		filePath := filepath.Join(wikiPath, entry.Name())

		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		content := string(data)

		advisoryMatch := advisoryIDRe.FindStringSubmatch(content)
		if advisoryMatch == nil {
			continue
		}
		advisoryID := advisoryMatch[1]

		dateMatch := issueDateRe.FindStringSubmatch(content)
		if dateMatch == nil {
			continue
		}
		date := dateMatch[1]

		cveIDs := cveIDRe.FindAllString(content, -1)
		if len(cveIDs) == 0 {
			continue
		}

		pageName := strings.TrimSuffix(entry.Name(), ".md")
		url := WikiBaseURL + "/" + pageName

		info := advisoryInfo{
			AdvisoryID: advisoryID,
			Date:       date,
			URL:        url,
		}

		for _, cveID := range cveIDs {
			key := advisoryKey{version: version, cveID: cveID}
			existing, exists := result[key]
			if !exists || date < existing.Date {
				result[key] = info
			}
		}
	}

	return result
}

func (m *Manager) mergeRecords(entries []cveEntry, photonVersion string) (map[string]map[string]interface{}, error) {
	namespace := fmt.Sprintf("photon:%s", photonVersion)

	grouped := make(map[string][]cveEntry)
	for _, entry := range entries {
		cveID := strings.TrimSpace(entry.CveID)
		if cveID == "" {
			continue
		}
		if strings.ToLower(cveID) == "bdsa" || strings.HasPrefix(strings.ToLower(cveID), "bdsa") {
			continue
		}
		grouped[cveID] = append(grouped[cveID], entry)
	}

	result := make(map[string]map[string]interface{})

	for cveID, pkgEntries := range grouped {
		var fixedIn []map[string]interface{}
		var vendorAdvisories []map[string]interface{}

		advisoryInfo, hasAdvisory := m.advisoryMap[advisoryKey{version: photonVersion, cveID: cveID}]

		for _, entry := range pkgEntries {
			if entry.Pkg == "" {
				continue
			}

			versionStr := entry.Version
			if versionStr == "" || versionStr == "NA" {
				continue
			}

			fi := map[string]interface{}{
				"name":          entry.Pkg,
				"version":       versionStr,
				"versionFormat": "rpm",
			}
			fixedIn = append(fixedIn, fi)
		}

		if len(fixedIn) == 0 {
			continue
		}

		metadata := map[string]interface{}{
			"source":  "photon-cve",
			"distro":  "photon",
			"version": photonVersion,
		}

		if hasAdvisory {
			metadata["issued"] = advisoryInfo.Date

			va := map[string]interface{}{
				"id":   advisoryInfo.AdvisoryID,
				"link": advisoryInfo.URL,
			}
			vendorAdvisories = append(vendorAdvisories, va)
			metadata["vendorAdvisory"] = vendorAdvisories
		}

		link := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)

		record := map[string]interface{}{
			"name":      cveID,
			"namespace": namespace,
			"severity":  "Unknown",
			"fixedIn":   fixedIn,
			"link":      link,
			"metadata":  metadata,
		}

		identifier := fmt.Sprintf("%s/%s", namespace, cveID)
		result[identifier] = record
	}

	return result, nil
}
