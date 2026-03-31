package rocky

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/shift/vulnz/internal/provider"
)

type apiResponse struct {
	Links      apiLinks                 `json:"links"`
	Advisories []map[string]interface{} `json:"advisories"`
}

type apiLinks struct {
	Next string `json:"next"`
}

type Manager struct {
	config  provider.Config
	client  *http.Client
	baseURL string
	urls    []string
}

func NewManager(config provider.Config) *Manager {
	return NewManagerWithURL(DefaultURL, config)
}

func NewManagerWithURL(baseURL string, config provider.Config) *Manager {
	return &Manager{
		config:  config,
		baseURL: baseURL,
		client: &http.Client{
			Timeout: config.HTTP.Timeout,
		},
	}
}

func (m *Manager) GetAllAdvisories(ctx context.Context) (map[string]map[string]interface{}, []string, error) {
	records := make(map[string]map[string]interface{})
	currentURL := m.baseURL

	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		pageRecords, nextURL, err := m.fetchPage(ctx, currentURL)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch page %s: %w", currentURL, err)
		}

		m.urls = append(m.urls, currentURL)
		m.config.Logger.InfoContext(ctx, "fetched Rocky Linux OSV page",
			"url", currentURL,
			"records_on_page", len(pageRecords),
		)

		for _, advisory := range pageRecords {
			m.normalizeEcosystem(advisory)

			id, ok := advisory["id"].(string)
			if !ok || id == "" {
				continue
			}
			records[id] = advisory
		}

		if nextURL == "" {
			break
		}

		currentURL = nextURL

		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}
	}

	return records, m.urls, nil
}

func (m *Manager) fetchPage(ctx context.Context, pageURL string) ([]map[string]interface{}, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", m.config.HTTP.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read response: %w", err)
	}

	var apiResp apiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, "", fmt.Errorf("parse JSON: %w", err)
	}

	nextURL := ""
	if apiResp.Links.Next != "" {
		if strings.HasPrefix(apiResp.Links.Next, "http") {
			nextURL = apiResp.Links.Next
		} else {
			base := m.baseURL
			if strings.HasSuffix(base, "/") {
				nextURL = base + strings.TrimPrefix(apiResp.Links.Next, "/")
			} else {
				nextURL = base + "/" + strings.TrimPrefix(apiResp.Links.Next, "/")
			}
		}
	}

	return apiResp.Advisories, nextURL, nil
}

func (m *Manager) normalizeEcosystem(advisory map[string]interface{}) {
	affected, ok := advisory["affected"].([]interface{})
	if !ok {
		return
	}

	for _, aff := range affected {
		pkg, ok := aff.(map[string]interface{})
		if !ok {
			continue
		}
		pkgInfo, ok := pkg["package"].(map[string]interface{})
		if !ok {
			continue
		}
		eco, ok := pkgInfo["ecosystem"].(string)
		if !ok {
			continue
		}
		if strings.HasPrefix(eco, "Rocky Linux:") {
			pkgInfo["ecosystem"] = "rocky:" + eco[len("Rocky Linux:"):]
		}
	}
}
