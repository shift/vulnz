package certfr

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/shift/vulnz/internal/provider"
)

const (
	advisoryIDPattern = `CERTFR-\d{4}-(?:AVI|ALE|ALR)-\d+`
	cvePattern        = `CVE-\d{4}-\d{4,}`
)

var (
	advisoryIDRe = regexp.MustCompile(advisoryIDPattern)
	cveRe        = regexp.MustCompile(cvePattern)
)

type rssFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	GUID        string `xml:"guid"`
	PubDate     string `xml:"pubDate"`
	Description string `xml:"description"`
}

type advisory struct {
	AdvisoryID  string
	Title       string
	Link        string
	Published   string
	Description string
	CVEs        []string
}

type Manager struct {
	url         string
	config      provider.Config
	client      *http.Client
	fetchedURLs []string
}

func NewManager(url string, config provider.Config) *Manager {
	return &Manager{
		url:         url,
		config:      config,
		client:      &http.Client{},
		fetchedURLs: []string{},
	}
}

func NewManagerWithURL(url string, config provider.Config, client *http.Client) *Manager {
	return &Manager{
		url:         url,
		config:      config,
		client:      client,
		fetchedURLs: []string{},
	}
}

func (m *Manager) URLs() []string {
	return m.fetchedURLs
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	items, err := m.fetchRSS(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch RSS feed: %w", err)
	}

	return m.process(items), nil
}

func (m *Manager) fetchRSS(ctx context.Context) ([]advisory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url, nil)
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

	m.fetchedURLs = append(m.fetchedURLs, m.url)

	if m.config.Workspace != "" {
		inputDir := filepath.Join(m.config.Workspace, "input")
		if err := os.MkdirAll(inputDir, 0755); err != nil {
			return nil, fmt.Errorf("create input directory: %w", err)
		}
		destPath := filepath.Join(inputDir, "cert_fr_feed.xml")
		if err := os.WriteFile(destPath, body, 0644); err != nil {
			return nil, fmt.Errorf("save RSS feed: %w", err)
		}
	}

	return ParseRSS(body)
}

func ParseRSS(data []byte) ([]advisory, error) {
	var feed rssFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("decode RSS XML: %w", err)
	}

	var advisories []advisory
	for _, item := range feed.Channel.Items {
		adv := extractAdvisory(item)
		if adv.AdvisoryID != "" {
			advisories = append(advisories, adv)
		}
	}

	return advisories, nil
}

func extractAdvisory(item rssItem) advisory {
	advisoryID := extractAdvisoryID(item.Title)
	if advisoryID == "" {
		advisoryID = extractAdvisoryID(item.Link)
	}

	title := cleanTitle(item.Title, advisoryID)

	return advisory{
		AdvisoryID:  advisoryID,
		Title:       title,
		Link:        item.Link,
		Published:   item.PubDate,
		Description: item.Description,
		CVEs:        ExtractCVEs(item.Description),
	}
}

func extractAdvisoryID(s string) string {
	return advisoryIDRe.FindString(s)
}

func ExtractCVEs(s string) []string {
	matches := cveRe.FindAllString(s, -1)
	seen := make(map[string]struct{}, len(matches))
	var unique []string
	for _, m := range matches {
		if _, ok := seen[m]; !ok {
			seen[m] = struct{}{}
			unique = append(unique, m)
		}
	}
	return unique
}

func cleanTitle(title, advisoryID string) string {
	if advisoryID == "" {
		return strings.TrimSpace(title)
	}
	t := strings.TrimSpace(title)
	t = strings.TrimPrefix(t, advisoryID)
	t = strings.TrimSpace(t)
	for _, prefix := range []string{":", "-", "(", ")"} {
		t = strings.TrimPrefix(t, prefix)
		t = strings.TrimSpace(t)
	}
	return t
}

func (m *Manager) process(items []advisory) map[string]map[string]interface{} {
	result := make(map[string]map[string]interface{})

	for _, adv := range items {
		isAlert := strings.Contains(adv.AdvisoryID, "ALE")
		advisoryType := "alerte"
		if !isAlert {
			advisoryType = "avis"
		}

		link := adv.Link
		if link == "" {
			link = fmt.Sprintf("https://www.cert.ssi.gouv.fr/%s/%s/", advisoryType, adv.AdvisoryID)
		}

		advisoryRef := map[string]interface{}{
			"id":   adv.AdvisoryID,
			"link": link,
		}

		fix := map[string]interface{}{
			"state":    "unknown",
			"versions": []interface{}{},
		}

		metadata := map[string]interface{}{
			"cert_fr_advisory_id": adv.AdvisoryID,
			"cert_fr_title":       adv.Title,
			"published":           adv.Published,
			"is_alert":            isAlert,
			"cves":                adv.CVEs,
			"affected_products":   []interface{}{},
			"source":              "cert-fr",
		}

		if len(adv.CVEs) > 0 {
			for _, cveID := range adv.CVEs {
				record := map[string]interface{}{
					"id":          cveID,
					"namespace":   "cert-fr:anssi",
					"description": adv.Description,
					"cvss":        []interface{}{},
					"fix":         fix,
					"advisories":  []interface{}{advisoryRef},
					"metadata":    metadata,
				}
				result[cveID] = record
			}
		} else {
			record := map[string]interface{}{
				"id":          adv.AdvisoryID,
				"namespace":   "cert-fr:anssi",
				"description": adv.Description,
				"cvss":        []interface{}{},
				"fix":         fix,
				"advisories":  []interface{}{advisoryRef},
				"metadata":    metadata,
			}
			result[adv.AdvisoryID] = record
		}
	}

	return result
}
