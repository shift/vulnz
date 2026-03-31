package amazon

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/utils/rpm"
	"github.com/shift/vulnz/internal/utils/vulnerability"
	"golang.org/x/net/html"
)

var (
	defaultAdvisories = map[string]string{
		"2":    "https://alas.aws.amazon.com/AL2/alas.rss",
		"2022": "https://alas.aws.amazon.com/AL2022/alas.rss",
		"2023": "https://alas.aws.amazon.com/AL2023/alas.rss",
	}

	severityMap = map[string]string{
		"low":       "Low",
		"medium":    "Medium",
		"important": "High",
		"critical":  "Critical",
	}

	titlePattern = regexp.MustCompile(`([^\s]+)\s+\(([^\)]+)\):.*`)

	allowedArchs = map[string]bool{
		"x86_64:": true,
		"noarch:": true,
	}
)

type rssItem struct {
	XMLName    xml.Name `xml:"item"`
	Title      string   `xml:"title"`
	Link       string   `xml:"link"`
	PubDate    string   `xml:"pubDate"`
	Descriptor string   `xml:"description"`
}

type rssFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Items []rssItem `xml:"item"`
}

type alasSummary struct {
	ID      string
	URL     string
	Sev     string
	CVEs    []string
	PubDate string
}

type fixedInEntry struct {
	Package string
	Version string
}

type Manager struct {
	config     provider.Config
	client     *http.Client
	urls       []string
	advisories map[string]string
}

func NewManager(config provider.Config) *Manager {
	return &Manager{
		config:     config,
		client:     &http.Client{Timeout: config.HTTP.Timeout},
		advisories: defaultAdvisories,
	}
}

func NewManagerWithAdvisories(config provider.Config, advisories map[string]string) *Manager {
	return &Manager{
		config:     config,
		client:     &http.Client{Timeout: config.HTTP.Timeout},
		advisories: advisories,
	}
}

func (m *Manager) URLs() []string {
	if len(m.urls) > 0 {
		return m.urls
	}
	urls := make([]string, 0, len(m.advisories))
	for _, u := range m.advisories {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	return urls
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	result := make(map[string]map[string]interface{})

	for version, rssURL := range m.advisories {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		m.urls = append(m.urls, rssURL)

		inputDir := filepath.Join(m.config.Workspace, "input")
		if err := os.MkdirAll(inputDir, 0755); err != nil {
			return nil, fmt.Errorf("create input directory: %w", err)
		}

		rssFile := filepath.Join(inputDir, fmt.Sprintf("%s_rss.xml", version))
		htmlDir := filepath.Join(inputDir, fmt.Sprintf("%s_html", version))
		if err := os.MkdirAll(htmlDir, 0755); err != nil {
			return nil, fmt.Errorf("create html directory: %w", err)
		}

		rssData, err := m.fetchRSS(ctx, rssURL, rssFile)
		if err != nil {
			return nil, fmt.Errorf("fetch RSS for version %s: %w", version, err)
		}

		summaries, err := m.parseRSS(rssData)
		if err != nil {
			return nil, fmt.Errorf("parse RSS for version %s: %w", version, err)
		}

		namespace := fmt.Sprintf("amzn:%s", version)

		type alasResult struct {
			alas alasSummary
			html string
			page string
		}

		var (
			mu      sync.Mutex
			results []alasResult
			wg      sync.WaitGroup
			sem     = make(chan struct{}, 20)
		)

		for _, alas := range summaries {
			wg.Add(1)
			go func(a alasSummary) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				select {
				case <-ctx.Done():
					return
				default:
				}

				alasFile := filepath.Join(htmlDir, a.ID)
				htmlContent, err := m.fetchALASPage(ctx, a.URL, alasFile)
				if err != nil {
					m.config.Logger.WarnContext(ctx, "failed to fetch ALAS page", "id", a.ID, "error", err)
					return
				}
				if htmlContent == "" {
					m.config.Logger.WarnContext(ctx, "skipping ALAS page", "id", a.ID)
					return
				}

				mu.Lock()
				results = append(results, alasResult{alas: a, html: htmlContent})
				mu.Unlock()
			}(alas)
		}
		wg.Wait()

		for _, r := range results {
			alas := r.alas
			htmlContent := r.html

			packages, description := parseHTML(htmlContent)

			fixedIn := make([]vulnerability.FixedIn, 0, len(packages))
			for _, pkg := range packages {
				fi := parsePackageFilename(pkg)
				if fi != nil {
					fixedIn = append(fixedIn, vulnerability.NewFixedIn(fi.Package, namespace, "rpm", fi.Version))
				}
			}

			sort.Slice(fixedIn, func(i, j int) bool {
				return fixedIn[i].Name < fixedIn[j].Name
			})

			cveEntries := make([]map[string]string, 0, len(alas.CVEs))
			for _, cve := range alas.CVEs {
				cveEntries = append(cveEntries, map[string]string{"Name": cve})
			}

			vuln := vulnerability.Vulnerability{
				Name:          alas.ID,
				NamespaceName: namespace,
				Description:   description,
				Severity:      normalizeSeverity(alas.Sev),
				Link:          alas.URL,
				FixedIn:       fixedIn,
				CVSS:          []vulnerability.CVSS{},
				Metadata: map[string]any{
					"CVE": cveEntries,
				},
			}

			identifier := fmt.Sprintf("%s/%s", strings.ToLower(namespace), strings.ToLower(alas.ID))
			result[identifier] = vuln.ToPayload()
		}
	}

	return result, nil
}

func (m *Manager) fetchRSS(ctx context.Context, rssURL, destPath string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rssURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch RSS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return nil, fmt.Errorf("save RSS: %w", err)
	}

	return body, nil
}

func (m *Manager) parseRSS(data []byte) ([]alasSummary, error) {
	var feed rssFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("parse XML: %w", err)
	}

	var summaries []alasSummary
	for _, item := range feed.Channel.Items {
		matches := titlePattern.FindStringSubmatch(strings.TrimSpace(item.Title))
		if len(matches) < 3 {
			continue
		}

		alasID := matches[1]
		sev := matches[2]

		desc := strings.TrimSpace(item.Descriptor)
		var cves []string
		if desc != "" {
			cleaned := strings.ReplaceAll(desc, " ", "")
			cves = strings.Split(cleaned, ",")
		}

		summaries = append(summaries, alasSummary{
			ID:      alasID,
			URL:     strings.TrimSpace(item.Link),
			Sev:     sev,
			CVEs:    cves,
			PubDate: strings.TrimSpace(item.PubDate),
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].ID < summaries[j].ID
	})

	return summaries, nil
}

func (m *Manager) fetchALASPage(ctx context.Context, url, destPath string) (string, error) {
	if data, err := os.ReadFile(destPath); err == nil && len(data) > 0 {
		return string(data), nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)

	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch ALAS page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return "", nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if err := os.WriteFile(destPath, body, 0644); err != nil {
		return "", fmt.Errorf("save ALAS page: %w", err)
	}

	return string(body), nil
}

func parseHTML(htmlContent string) (packages []string, description string) {
	tokenizer := html.NewTokenizer(strings.NewReader(htmlContent))

	var divDepth int
	inNewPackages := false
	inIssueOverview := false
	archHit := false

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}

		switch tt {
		case html.StartTagToken:
			tagName, hasAttr := tokenizer.TagName()
			if hasAttr {
				attrs := parseAttrs(tokenizer)
				for _, attr := range attrs {
					if attr.Key == "id" && attr.Val == "new_packages" {
						inNewPackages = true
						archHit = false
						divDepth = 0
						break
					}
					if attr.Key == "id" && attr.Val == "issue_overview" {
						inIssueOverview = true
						divDepth = 0
						break
					}
				}
			}
			if inNewPackages || inIssueOverview {
				if string(tagName) == "div" {
					divDepth++
				}
			}

		case html.EndTagToken:
			if inNewPackages || inIssueOverview {
				tagName, _ := tokenizer.TagName()
				if string(tagName) == "div" {
					divDepth--
					if divDepth <= 0 {
						inNewPackages = false
						inIssueOverview = false
						archHit = false
					}
				}
			}

		case html.TextToken:
			rawText := string(tokenizer.Text())
			lines := strings.Split(rawText, "\n")
			for _, line := range lines {
				text := strings.TrimSpace(line)
				if text == "" {
					continue
				}

				if inNewPackages {
					if allowedArchs[text] {
						archHit = true
					} else if strings.HasSuffix(text, ":") {
						archHit = false
					} else if archHit {
						packages = append(packages, text)
					}
				}

				if inIssueOverview && text != "Issue Overview:" {
					description += text
				}
			}
		}
	}

	return packages, description
}

func parseAttrs(tokenizer *html.Tokenizer) []html.Attribute {
	var attrs []html.Attribute
	for {
		key, val, more := tokenizer.TagAttr()
		attrs = append(attrs, html.Attribute{Key: string(key), Val: string(val)})
		if !more {
			break
		}
	}
	return attrs
}

func parsePackageFilename(filename string) *fixedInEntry {
	if !strings.HasSuffix(filename, ".rpm") {
		filename = filename + ".rpm"
	}

	basename := strings.TrimSuffix(filename, ".rpm")

	name, versionRelease := splitNVR(basename)
	if name == "" || versionRelease == "" {
		return nil
	}

	v, err := rpm.Parse(versionRelease)
	if err != nil {
		return nil
	}

	return &fixedInEntry{
		Package: name,
		Version: v.String(),
	}
}

func splitNVR(basename string) (name, versionRelease string) {
	parts := strings.Split(basename, "-")
	if len(parts) < 2 {
		return "", ""
	}

	i := 1
	for i < len(parts) {
		if len(parts[i]) > 0 && parts[i][0] >= '0' && parts[i][0] <= '9' {
			break
		}
		i++
	}

	if i >= len(parts) {
		return "", ""
	}

	return strings.Join(parts[:i], "-"), strings.Join(parts[i:], "-")
}

func normalizeSeverity(sev string) string {
	if normalized, ok := severityMap[strings.ToLower(sev)]; ok {
		return normalized
	}
	return "Unknown"
}
