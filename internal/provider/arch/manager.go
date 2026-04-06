package arch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shift/vulnz/internal/provider"
)

const (
	DefaultAllURL = "https://security.archlinux.org/all.json"
	Namespace     = "arch:rolling"
	asaBatchSize  = 10
	asaMaxConc    = 2
	asaBatchDelay = 1 * time.Second
	securityBase  = "https://security.archlinux.org"
)

var severityMapping = map[string]string{
	"Critical": "Critical",
	"High":     "High",
	"Medium":   "Medium",
	"Low":      "Low",
}

var asaDateRegex = regexp.MustCompile(`(?m)^Date\s*:\s*(\d{4}-\d{2}-\d{2})`)

type advisoryEntry struct {
	Name       string   `json:"name"`
	Group      int      `json:"group"`
	Severity   string   `json:"severity"`
	Type       string   `json:"type"`
	Status     string   `json:"status"`
	Affected   string   `json:"affected"`
	Fixed      string   `json:"fixed"`
	Issues     []string `json:"issues"`
	Advisories []string `json:"advisories"`
}

type PackageInfo struct {
	Name    string
	Version string
}

type FixedIn struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	VersionFormat string `json:"versionFormat"`
}

type CVEReference struct {
	Name string `json:"name"`
	Link string `json:"link"`
}

type Metadata struct {
	Issued     string         `json:"issued,omitempty"`
	CVE        []CVEReference `json:"cve,omitempty"`
	Advisories []string       `json:"advisories,omitempty"`
}

type VulnerabilityRecord struct {
	Name        string    `json:"name"`
	Namespace   string    `json:"namespace"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Link        string    `json:"link"`
	FixedIn     []FixedIn `json:"fixedIn"`
	Metadata    Metadata  `json:"metadata"`
}

type Manager struct {
	allURL string
	config provider.Config
	client *http.Client
}

func NewManager(config provider.Config) *Manager {
	return &Manager{
		allURL: DefaultAllURL,
		config: config,
		client: &http.Client{Timeout: config.HTTP.Timeout},
	}
}

func NewManagerWithURL(allURL string, config provider.Config) *Manager {
	return &Manager{
		allURL: allURL,
		config: config,
		client: &http.Client{Timeout: config.HTTP.Timeout},
	}
}

func (m *Manager) URLs() []string {
	return []string{m.allURL}
}

func (m *Manager) Get(ctx context.Context) (map[string]VulnerabilityRecord, error) {
	entries, err := m.fetchAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch arch advisories: %w", err)
	}

	var active []advisoryEntry
	for _, e := range entries {
		if e.Status != "Not affected" {
			active = append(active, e)
		}
	}

	asaIDs := m.collectASAIDs(active)
	asaDates := m.prefetchASADates(ctx, asaIDs)

	records := make(map[string]VulnerabilityRecord)
	for _, entry := range active {
		for id, rec := range m.buildRecords(entry, asaDates) {
			records[id] = rec
		}
	}

	return records, nil
}

func (m *Manager) fetchAll(ctx context.Context) ([]advisoryEntry, error) {
	inputDir := filepath.Join(m.config.Workspace, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, fmt.Errorf("create input directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.allURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch all.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	destPath := filepath.Join(inputDir, "all.json")
	tmpPath := destPath + ".tmp"

	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return nil, fmt.Errorf("stream response to file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close temp file: %w", err)
	}

	var entries []advisoryEntry
	fh, err := os.Open(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("open temp file for decode: %w", err)
	}
	defer fh.Close()

	if err := json.NewDecoder(fh).Decode(&entries); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	os.Rename(tmpPath, destPath)

	return entries, nil
}

func (m *Manager) collectASAIDs(entries []advisoryEntry) []string {
	seen := make(map[string]struct{})
	var ids []string
	for _, e := range entries {
		if e.Fixed == "" {
			continue
		}
		for _, asa := range e.Advisories {
			if _, exists := seen[asa]; !exists {
				seen[asa] = struct{}{}
				ids = append(ids, asa)
			}
		}
	}
	return ids
}

func (m *Manager) prefetchASADates(ctx context.Context, asaIDs []string) map[string]string {
	results := make(map[string]string)
	if len(asaIDs) == 0 {
		return results
	}

	var mu sync.Mutex
	sem := make(chan struct{}, asaMaxConc)

	for i := 0; i < len(asaIDs); i += asaBatchSize {
		end := i + asaBatchSize
		if end > len(asaIDs) {
			end = len(asaIDs)
		}
		batch := asaIDs[i:end]

		var wg sync.WaitGroup
		for _, id := range batch {
			wg.Add(1)
			go func(asaID string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				date := m.fetchASADate(ctx, asaID)
				mu.Lock()
				results[asaID] = date
				mu.Unlock()
			}(id)
		}
		wg.Wait()

		if end < len(asaIDs) {
			select {
			case <-ctx.Done():
				return results
			case <-time.After(asaBatchDelay):
			}
		}
	}

	return results
}

const maxASASize = 64 * 1024 // 64KB cap for individual advisory pages

func (m *Manager) fetchASADate(ctx context.Context, asaID string) string {
	base := m.allURL
	if idx := strings.LastIndex(base, "/"); idx != -1 {
		base = base[:idx]
	}
	url := fmt.Sprintf("%s/%s/raw", base, asaID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var buf [maxASASize]byte
	n, _ := io.ReadFull(io.LimitReader(resp.Body, maxASASize), buf[:])

	return ParseASA(string(buf[:n]))
}

func (m *Manager) buildRecords(entry advisoryEntry, asaDates map[string]string) map[string]VulnerabilityRecord {
	records := make(map[string]VulnerabilityRecord)

	severity, ok := severityMapping[entry.Severity]
	if !ok {
		severity = "Unknown"
	}

	fixedPkgs := ParsePackages(entry.Fixed)
	var fixedIn []FixedIn
	if len(fixedPkgs) > 0 {
		for _, pkg := range fixedPkgs {
			fixedIn = append(fixedIn, FixedIn{
				Name:          pkg.Name,
				Version:       pkg.Version,
				VersionFormat: "pacman",
			})
		}
	} else {
		affectedPkgs := ParsePackages(entry.Affected)
		for _, pkg := range affectedPkgs {
			fixedIn = append(fixedIn, FixedIn{
				Name:          pkg.Name,
				Version:       "None",
				VersionFormat: "pacman",
			})
		}
	}

	var issued string
	if len(entry.Advisories) > 0 {
		var dates []string
		for _, asa := range entry.Advisories {
			if d, ok := asaDates[asa]; ok && d != "" {
				dates = append(dates, d)
			}
		}
		if len(dates) > 0 {
			sort.Strings(dates)
			issued = dates[0]
		}
	}

	var cveRefs []CVEReference
	for _, cve := range entry.Issues {
		cveRefs = append(cveRefs, CVEReference{
			Name: cve,
			Link: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve),
		})
	}

	metadata := Metadata{
		Issued:     issued,
		CVE:        cveRefs,
		Advisories: entry.Advisories,
	}

	description := entry.Type
	if description == "" || description == "unknown" {
		description = fmt.Sprintf("Arch vulnerability %s", entry.Name)
	}

	link := fmt.Sprintf("%s/%s", securityBase, entry.Name)

	if len(entry.Issues) > 0 {
		for _, cve := range entry.Issues {
			records[cve] = VulnerabilityRecord{
				Name:        cve,
				Namespace:   Namespace,
				Description: description,
				Severity:    severity,
				Link:        link,
				FixedIn:     fixedIn,
				Metadata:    metadata,
			}
		}
	} else {
		records[entry.Name] = VulnerabilityRecord{
			Name:        entry.Name,
			Namespace:   Namespace,
			Description: description,
			Severity:    severity,
			Link:        link,
			FixedIn:     fixedIn,
			Metadata:    metadata,
		}
	}

	return records
}

func ParsePackages(s string) []PackageInfo {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	var result []PackageInfo
	parts := strings.Split(s, ", ")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, " ")
		if idx == -1 {
			result = append(result, PackageInfo{Name: part})
			continue
		}
		result = append(result, PackageInfo{
			Name:    part[:idx],
			Version: part[idx+1:],
		})
	}
	return result
}

func ParseASA(text string) string {
	match := asaDateRegex.FindStringSubmatch(text)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}
