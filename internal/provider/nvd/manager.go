package nvd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shift/vulnz/internal/provider"
)

type Manager struct {
	config    provider.Config
	client    *http.Client
	api       *APIClient
	overrides *Overrides
	urls      []string
	apiKey    string
	retries   int
}

func NewManager(config provider.Config) *Manager {
	return newManager(config, CVEAPIURL)
}

func NewManagerWithAPIURL(config provider.Config, apiURL string) *Manager {
	return newManager(config, apiURL)
}

func newManager(config provider.Config, apiURL string) *Manager {
	apiKey := os.Getenv("NVD_API_KEY")

	retries := config.HTTP.MaxRetries
	if retries <= 0 {
		retries = 10
	}

	timeout := config.HTTP.Timeout
	if timeout <= 0 {
		timeout = 125 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
	}

	inputPath := filepath.Join(config.Workspace, "input")

	return &Manager{
		config:    config,
		client:    client,
		api:       NewAPIClientWithURL(client, apiURL, apiKey, config.Logger, retries),
		overrides: NewOverrides(false, "https://github.com/anchore/nvd-data-overrides/archive/refs/heads/main.tar.gz", inputPath, config.Logger, client),
		urls:      []string{apiURL},
		apiKey:    apiKey,
		retries:   retries,
	}
}

func NewManagerWithOverrides(config provider.Config, overridesEnabled bool, overridesURL string) *Manager {
	m := NewManager(config)
	m.overrides = NewOverrides(overridesEnabled, overridesURL, filepath.Join(config.Workspace, "input"), config.Logger, m.client)
	return m
}

func NewManagerWithOverridesAndURL(config provider.Config, overridesEnabled bool, overridesURL, apiURL string) *Manager {
	m := NewManagerWithAPIURL(config, apiURL)
	m.overrides = NewOverrides(overridesEnabled, overridesURL, filepath.Join(config.Workspace, "input"), config.Logger, m.client)
	return m
}

func (m *Manager) URLs() []string {
	return m.urls
}

func (m *Manager) SetRetryWait(d time.Duration) {
	m.api.SetRetryWait(d)
}

func (m *Manager) Get(ctx context.Context, lastUpdated *time.Time) (map[string]map[string]interface{}, error) {
	if m.overrides.enabled {
		if err := m.overrides.Download(ctx); err != nil {
			m.config.Logger.WarnContext(ctx, "failed to download overrides, continuing without", "error", err)
		}
	}

	var records []map[string]interface{}
	var err error

	if lastUpdated != nil {
		since := time.Since(*lastUpdated)
		if since >= time.Duration(MaxDateRangeDays)*24*time.Hour {
			m.config.Logger.InfoContext(ctx, "last sync too old for incremental, downloading all",
				"days_ago", int(since.Hours()/24),
				"max_days", MaxDateRangeDays,
			)
			records, err = m.api.FetchAll(ctx)
		} else {
			records, err = m.api.FetchUpdates(ctx, *lastUpdated)
		}
	} else {
		records, err = m.api.FetchAll(ctx)
	}

	if err != nil {
		return nil, fmt.Errorf("fetch NVD data: %w", err)
	}

	result := make(map[string]map[string]interface{}, len(records))

	for _, record := range records {
		cveID, ok := record["id"].(string)
		if !ok {
			continue
		}

		recordID := CVEToID(cveID)

		_, recordWithOverrides := ApplyOverride(cveID, record, m.overrides.CVE(cveID))

		result[recordID] = recordWithOverrides
	}

	return result, nil
}

func CVEToID(cve string) string {
	parts := strings.SplitN(cve, "-", 3)
	if len(parts) >= 2 {
		return strings.ToLower(parts[1] + "/" + cve)
	}
	return strings.ToLower(cve)
}

func RecordIDToCVE(recordID string) string {
	parts := strings.SplitN(recordID, "/", 2)
	if len(parts) >= 2 {
		return strings.ToUpper(parts[1])
	}
	return strings.ToUpper(recordID)
}
