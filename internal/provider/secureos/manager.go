package secureos

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/shift/vulnz/internal/provider"
)

type metadata struct {
	LatestURL string `json:"latest_url"`
	SHA256    string `json:"sha256"`
}

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
	metadataURL string
	config      provider.Config
	client      *http.Client
}

func NewManager(url string, config provider.Config) *Manager {
	return &Manager{
		metadataURL: url,
		config:      config,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

func NewManagerWithURL(metadataURL string, config provider.Config) *Manager {
	return NewManager(metadataURL, config)
}

func (m *Manager) URLs() []string {
	return []string{m.metadataURL}
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	meta, err := m.fetchMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch secureos metadata: %w", err)
	}

	secdbURL := meta.LatestURL
	if !strings.HasPrefix(secdbURL, "http://") && !strings.HasPrefix(secdbURL, "https://") {
		base, err := url.Parse(m.metadataURL)
		if err == nil {
			rel, err := url.Parse(secdbURL)
			if err == nil {
				secdbURL = base.ResolveReference(rel).String()
			}
		}
	}

	gzData, err := m.downloadSecDB(ctx, secdbURL)
	if err != nil {
		return nil, fmt.Errorf("download secureos secdb: %w", err)
	}

	if err := m.verifySHA256(gzData, meta.SHA256); err != nil {
		return nil, fmt.Errorf("verify secureos secdb: %w", err)
	}

	db, err := m.parseSecDB(gzData)
	if err != nil {
		return nil, fmt.Errorf("parse secureos secdb: %w", err)
	}

	records, err := m.normalize(db)
	if err != nil {
		return nil, fmt.Errorf("normalize secureos secdb: %w", err)
	}

	return records, nil
}

func (m *Manager) fetchMetadata(ctx context.Context) (*metadata, error) {
	inputDir := filepath.Join(m.config.Workspace, "input", "secdb")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, fmt.Errorf("create input directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create metadata request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read metadata response: %w", err)
	}

	destPath := filepath.Join(inputDir, "latest.json")
	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return nil, fmt.Errorf("save metadata: %w", err)
	}

	var meta metadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("parse metadata JSON: %w", err)
	}

	if meta.LatestURL == "" || meta.SHA256 == "" {
		return nil, fmt.Errorf("metadata must contain 'latest_url' and 'sha256' fields")
	}

	return &meta, nil
}

func (m *Manager) downloadSecDB(ctx context.Context, url string) ([]byte, error) {
	inputDir := filepath.Join(m.config.Workspace, "input", "secdb")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create secdb request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch secdb: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read secdb response: %w", err)
	}

	gzFilename := filepath.Base(url)
	destPath := filepath.Join(inputDir, gzFilename)
	if err := os.WriteFile(destPath, data, 0644); err != nil {
		return nil, fmt.Errorf("save secdb: %w", err)
	}

	return data, nil
}

func (m *Manager) verifySHA256(data []byte, expected string) error {
	h := sha256.New()
	buf := bytes.NewReader(data)
	block := make([]byte, 4096)

	for {
		n, err := buf.Read(block)
		if n > 0 {
			h.Write(block[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read data for sha256: %w", err)
		}
	}

	calculated := fmt.Sprintf("%x", h.Sum(nil))
	if calculated != expected {
		return fmt.Errorf("sha256 mismatch: expected %s, got %s", expected, calculated)
	}

	return nil
}

func (m *Manager) parseSecDB(gzData []byte) (*secDB, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(gzData))
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzReader.Close()

	decompressed, err := io.ReadAll(gzReader)
	if err != nil {
		return nil, fmt.Errorf("decompress gzip: %w", err)
	}

	inputDir := filepath.Join(m.config.Workspace, "input", "secdb")
	jsonPath := filepath.Join(inputDir, "secdb.json")
	if err := os.WriteFile(jsonPath, decompressed, 0644); err != nil {
		return nil, fmt.Errorf("save decompressed secdb: %w", err)
	}

	var db secDB
	if err := json.Unmarshal(decompressed, &db); err != nil {
		return nil, fmt.Errorf("parse secdb JSON: %w", err)
	}

	return &db, nil
}

func (m *Manager) normalize(db *secDB) (map[string]map[string]interface{}, error) {
	result := make(map[string]map[string]interface{})
	seenVulnPkg := make(map[string]bool)

	for _, entry := range db.Packages {
		pkgName := entry.Pkg.Name
		secfixes := entry.Pkg.SecFixes

		sortedVersions := sortVersions(secfixes)
		allVersions := make([]string, len(sortedVersions))
		copy(allVersions, sortedVersions)
		for v := range secfixes {
			if !isSpecialVersion(v) && !containsVersion(sortedVersions, v) {
				allVersions = append(allVersions, v)
			}
		}
		allVersions = appendSpecialVersions(allVersions, secfixes)

		for _, fixVersion := range allVersions {
			rawVulns := secfixes[fixVersion]
			for _, rawID := range rawVulns {
				vid := strings.TrimSpace(rawID)
				if vid == "" {
					continue
				}

				if _, exists := result[vid]; !exists {
					link := ""
					if strings.HasPrefix(vid, "CVE-") {
						link = fmt.Sprintf("https://security.secureos.io/%s", vid)
					}
					result[vid] = map[string]interface{}{
						"Vulnerability": map[string]interface{}{
							"Name":          vid,
							"NamespaceName": Namespace,
							"Link":          link,
							"Severity":      "Unknown",
							"FixedIn":       []interface{}{},
						},
					}
				}

				vulnMap := result[vid]["Vulnerability"].(map[string]interface{})
				fixedInList := vulnMap["FixedIn"].([]interface{})

				fixedEl := map[string]interface{}{
					"Name":          pkgName,
					"Version":       fixVersion,
					"VersionFormat": "apk",
					"NamespaceName": Namespace,
				}

				key := vid + ":" + pkgName
				isFirst := !seenVulnPkg[key]
				if !isSpecialVersion(fixVersion) {
					seenVulnPkg[key] = true
					if !isFirst {
						_, revision := parseAPKVersion(fixVersion)
						if revision > 0 {
							baseR0 := getBaseVersionWithR0(fixVersion)
							fixedEl["VulnerableRange"] = fmt.Sprintf(">=%s, <%s", baseR0, fixVersion)
						}
					}
				}

				fixedInList = append(fixedInList, fixedEl)
				vulnMap["FixedIn"] = fixedInList
			}
		}
	}

	return result, nil
}

func parseAPKVersion(ver string) ([]string, int) {
	revision := 0
	versionStr := ver

	if idx := strings.LastIndex(ver, "-r"); idx != -1 {
		versionStr = ver[:idx]
		if r, err := strconv.Atoi(ver[idx+2:]); err == nil {
			revision = r
		}
	}

	parts := strings.Split(versionStr, ".")
	return parts, revision
}

func compareAPKVersions(a, b string) int {
	if a == b {
		return 0
	}

	partsA, revA := parseAPKVersion(a)
	partsB, revB := parseAPKVersion(b)

	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		var pA, pB string
		if i < len(partsA) {
			pA = partsA[i]
		}
		if i < len(partsB) {
			pB = partsB[i]
		}

		nA, errA := strconv.Atoi(pA)
		nB, errB := strconv.Atoi(pB)

		if errA == nil && errB == nil {
			if nA < nB {
				return -1
			}
			if nA > nB {
				return 1
			}
		} else {
			if pA < pB {
				return -1
			}
			if pA > pB {
				return 1
			}
		}
	}

	if revA < revB {
		return -1
	}
	if revA > revB {
		return 1
	}
	return 0
}

func getBaseVersionWithR0(ver string) string {
	if idx := strings.LastIndex(ver, "-r"); idx != -1 {
		return ver[:idx] + "-r0"
	}
	return ver + "-r0"
}

func isSpecialVersion(v string) bool {
	return v == "" || v == "0" || v == "None"
}

func containsVersion(versions []string, v string) bool {
	for _, ver := range versions {
		if ver == v {
			return true
		}
	}
	return false
}

func appendSpecialVersions(versions []string, secfixes map[string][]string) []string {
	for v := range secfixes {
		if isSpecialVersion(v) && !containsVersion(versions, v) {
			versions = append(versions, v)
		}
	}
	return versions
}

func sortVersions(secfixes map[string][]string) []string {
	var versions []string
	for v := range secfixes {
		if !isSpecialVersion(v) {
			versions = append(versions, v)
		}
	}
	sort.Slice(versions, func(i, j int) bool {
		return compareAPKVersions(versions[i], versions[j]) < 0
	})
	return versions
}
