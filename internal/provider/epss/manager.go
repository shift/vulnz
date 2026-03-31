package epss

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	vulnzhttp "github.com/shift/vulnz/internal/http"
	"github.com/shift/vulnz/internal/provider"
)

type Record struct {
	Cve        string  `json:"cve"`
	Epss       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
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

func NewManagerWithURL(url string, config provider.Config) *Manager {
	return NewManager(url, config)
}

func (m *Manager) URLs() []string {
	return []string{m.url}
}

func (m *Manager) Get(ctx context.Context) (map[string]map[string]interface{}, error) {
	records, err := m.download(ctx)
	if err != nil {
		return nil, fmt.Errorf("download EPSS data: %w", err)
	}

	result := make(map[string]map[string]interface{}, len(records))
	for _, rec := range records {
		if rec.Cve == "" {
			continue
		}
		result[rec.Cve] = map[string]interface{}{
			"cve":        rec.Cve,
			"epss":       rec.Epss,
			"percentile": rec.Percentile,
			"date":       rec.Date,
			"namespace":  "epss",
		}
	}

	return result, nil
}

func (m *Manager) download(ctx context.Context) ([]Record, error) {
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
		return nil, fmt.Errorf("fetch EPSS data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzReader.Close()

	limitedReader := io.LimitReader(gzReader, vulnzhttp.MaxResponseSize)

	var buf bytes.Buffer
	tee := io.TeeReader(limitedReader, &buf)

	records, err := m.parse(tee)
	if err != nil {
		return nil, err
	}

	destPath := filepath.Join(inputDir, "epss_data.csv")
	if err := os.WriteFile(destPath, buf.Bytes(), 0644); err != nil {
		return nil, fmt.Errorf("save EPSS data: %w", err)
	}

	return records, nil
}

func (m *Manager) parse(r io.Reader) ([]Record, error) {
	var records []Record
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	var scoreDate string
	headerParsed := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if scoreDate == "" {
			if extracted := extractDateFromComment(line); extracted != "" {
				scoreDate = extracted
			}
			continue
		}

		if !headerParsed {
			if !strings.HasPrefix(line, "CVE-") {
				headerParsed = true
				continue
			}
		}

		if !strings.HasPrefix(line, "CVE-") {
			continue
		}

		rec, err := parseRecord(line, scoreDate)
		if err != nil {
			continue
		}
		records = append(records, *rec)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan EPSS data: %w", err)
	}

	if scoreDate == "" {
		return nil, fmt.Errorf("couldn't find score_date in EPSS data")
	}

	return records, nil
}

func extractDateFromComment(line string) string {
	if !strings.HasPrefix(line, "#") || !strings.Contains(line, "score_date") {
		return ""
	}
	for _, field := range strings.Split(line, ",") {
		field = strings.TrimSpace(field)
		if strings.HasPrefix(field, "score_date") {
			parts := strings.SplitN(field, ":", 2)
			if len(parts) == 2 {
				datePart := strings.SplitN(parts[1], "T", 2)
				return strings.TrimSpace(datePart[0])
			}
		}
	}
	return ""
}

func parseRecord(line, date string) (*Record, error) {
	tokens := strings.Split(line, ",")
	if len(tokens) < 3 {
		return nil, fmt.Errorf("invalid record: %s", line)
	}

	cve := strings.TrimSpace(tokens[0])
	if cve == "" {
		return nil, fmt.Errorf("empty CVE")
	}

	epss, err := strconv.ParseFloat(strings.TrimSpace(tokens[1]), 64)
	if err != nil {
		return nil, fmt.Errorf("invalid epss value: %w", err)
	}

	percentile, err := strconv.ParseFloat(strings.TrimSpace(tokens[2]), 64)
	if err != nil {
		return nil, fmt.Errorf("invalid percentile value: %w", err)
	}

	return &Record{
		Cve:        cve,
		Epss:       epss,
		Percentile: percentile,
		Date:       date,
	}, nil
}
