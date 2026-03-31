package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	CVEAPIURL         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	MaxDateRangeDays  = 120
	MaxResultsPerPage = 2000
)

type nvdResponse struct {
	ResultsPerPage  int                  `json:"resultsPerPage"`
	StartIndex      int                  `json:"startIndex"`
	TotalResults    int                  `json:"totalResults"`
	Vulnerabilities []vulnerabilityEntry `json:"vulnerabilities"`
	Message         string               `json:"message,omitempty"`
}

type vulnerabilityEntry struct {
	CVE json.RawMessage `json:"cve"`
}

type APIClient struct {
	client    *http.Client
	apiURL    string
	apiKey    string
	logger    *slog.Logger
	retries   int
	retryWait time.Duration
}

func NewAPIClient(client *http.Client, apiKey string, logger *slog.Logger, retries int) *APIClient {
	return &APIClient{
		client:    client,
		apiURL:    CVEAPIURL,
		apiKey:    apiKey,
		logger:    logger,
		retries:   retries,
		retryWait: 30 * time.Second,
	}
}

func NewAPIClientWithURL(client *http.Client, apiURL, apiKey string, logger *slog.Logger, retries int) *APIClient {
	return &APIClient{
		client:    client,
		apiURL:    apiURL,
		apiKey:    apiKey,
		logger:    logger,
		retries:   retries,
		retryWait: 30 * time.Second,
	}
}

func (a *APIClient) SetRetryWait(d time.Duration) {
	a.retryWait = d
}

type CVECallback func(cveID string, record map[string]interface{}) error

func (a *APIClient) FetchAll(ctx context.Context) ([]map[string]interface{}, error) {
	a.logger.InfoContext(ctx, "downloading all CVEs")
	return a.fetchPages(ctx, nil)
}

func (a *APIClient) FetchAllStream(ctx context.Context, cb CVECallback) error {
	a.logger.InfoContext(ctx, "downloading all CVEs (streaming)")
	return a.streamPages(ctx, nil, cb)
}

func (a *APIClient) FetchUpdates(ctx context.Context, lastUpdated time.Time) ([]map[string]interface{}, error) {
	now := time.Now().UTC()
	params := map[string]string{
		"lastModStartDate": lastUpdated.UTC().Format(time.RFC3339),
		"lastModEndDate":   now.Format(time.RFC3339),
	}
	a.logger.InfoContext(ctx, "downloading CVE updates", "since", lastUpdated.UTC(), "until", now)
	return a.fetchPages(ctx, params)
}

func (a *APIClient) FetchUpdatesStream(ctx context.Context, lastUpdated time.Time, cb CVECallback) error {
	now := time.Now().UTC()
	params := map[string]string{
		"lastModStartDate": lastUpdated.UTC().Format(time.RFC3339),
		"lastModEndDate":   now.Format(time.RFC3339),
	}
	a.logger.InfoContext(ctx, "downloading CVE updates (streaming)", "since", lastUpdated.UTC(), "until", now)
	return a.streamPages(ctx, params, cb)
}

func (a *APIClient) fetchPages(ctx context.Context, params map[string]string) ([]map[string]interface{}, error) {
	if params == nil {
		params = make(map[string]string)
	}
	params["resultsPerPage"] = strconv.Itoa(MaxResultsPerPage)

	allRecords := make([]map[string]interface{}, 0)
	page := 1

	for {
		a.logger.DebugContext(ctx, "fetching NVD page", "page", page)

		var resp *nvdResponse
		var err error
		for attempt := 0; attempt <= a.retries; attempt++ {
			resp, err = a.doRequest(ctx, a.apiURL, params)
			if err == nil {
				break
			}
			if attempt < a.retries {
				a.logger.WarnContext(ctx, "request failed, retrying", "attempt", attempt+1, "error", err)
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(a.retryWait):
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("NVD API request failed after retries: %w", err)
		}

		if resp.Message != "" {
			return nil, fmt.Errorf("NVD API error: %s", resp.Message)
		}

		for _, vuln := range resp.Vulnerabilities {
			var record map[string]interface{}
			if err := json.Unmarshal(vuln.CVE, &record); err != nil {
				a.logger.WarnContext(ctx, "failed to unmarshal CVE record", "error", err)
				continue
			}
			allRecords = append(allRecords, record)
		}

		if resp.TotalResults == 0 || resp.ResultsPerPage == 0 {
			break
		}

		pages := resp.TotalResults / resp.ResultsPerPage
		nextIndex := page * resp.ResultsPerPage

		if page > pages || nextIndex >= resp.TotalResults {
			break
		}

		params["startIndex"] = strconv.Itoa(nextIndex)
		page++
	}

	a.logger.InfoContext(ctx, "fetched NVD records", "total", len(allRecords))
	return allRecords, nil
}

func (a *APIClient) streamPages(ctx context.Context, params map[string]string, cb CVECallback) error {
	if params == nil {
		params = make(map[string]string)
	}
	params["resultsPerPage"] = strconv.Itoa(MaxResultsPerPage)

	page := 1
	total := 0

	for {
		a.logger.DebugContext(ctx, "fetching NVD page", "page", page)

		var resp *nvdResponse
		var err error
		for attempt := 0; attempt <= a.retries; attempt++ {
			resp, err = a.doRequest(ctx, a.apiURL, params)
			if err == nil {
				break
			}
			if attempt < a.retries {
				a.logger.WarnContext(ctx, "request failed, retrying", "attempt", attempt+1, "error", err)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(a.retryWait):
				}
			}
		}
		if err != nil {
			return fmt.Errorf("NVD API request failed after retries: %w", err)
		}

		if resp.Message != "" {
			return fmt.Errorf("NVD API error: %s", resp.Message)
		}

		for _, vuln := range resp.Vulnerabilities {
			var record map[string]interface{}
			if err := json.Unmarshal(vuln.CVE, &record); err != nil {
				a.logger.WarnContext(ctx, "failed to unmarshal CVE record", "error", err)
				continue
			}
			cveID, ok := record["id"].(string)
			if !ok {
				continue
			}
			if err := cb(cveID, record); err != nil {
				return fmt.Errorf("callback for %s: %w", cveID, err)
			}
			total++
		}

		if resp.TotalResults == 0 || resp.ResultsPerPage == 0 {
			break
		}

		pages := resp.TotalResults / resp.ResultsPerPage
		nextIndex := page * resp.ResultsPerPage

		if page > pages || nextIndex >= resp.TotalResults {
			break
		}

		params["startIndex"] = strconv.Itoa(nextIndex)
		page++
	}

	a.logger.InfoContext(ctx, "streamed NVD records", "total", total)
	return nil
}

func (a *APIClient) doRequest(ctx context.Context, apiURL string, params map[string]string) (*nvdResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		req.Header.Set("apiKey", a.apiKey)
	}

	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited (status %d)", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	var result nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}
