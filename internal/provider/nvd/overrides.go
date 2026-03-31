package nvd

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	overridesFileName = "nvd-overrides.tar.gz"
	overridesDirName  = "nvd-overrides"
)

type Overrides struct {
	enabled   bool
	url       string
	inputPath string
	logger    *slog.Logger
	client    *http.Client
	cache     map[string]map[string]interface{}
	loaded    bool
}

func NewOverrides(enabled bool, url, inputPath string, logger *slog.Logger, client *http.Client) *Overrides {
	return &Overrides{
		enabled:   enabled,
		url:       url,
		inputPath: inputPath,
		logger:    logger,
		client:    client,
	}
}

func (o *Overrides) Download(ctx context.Context) error {
	if !o.enabled {
		o.logger.DebugContext(ctx, "overrides not enabled, skipping download")
		return nil
	}

	o.logger.InfoContext(ctx, "downloading NVD overrides", "url", o.url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "vulnz-go/1.0")

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("download overrides: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d downloading overrides", resp.StatusCode)
	}

	filePath := filepath.Join(o.inputPath, overridesFileName)
	if err := os.MkdirAll(o.inputPath, 0755); err != nil {
		return fmt.Errorf("create input dir: %w", err)
	}

	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("create overrides file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write overrides file: %w", err)
	}

	extractPath := filepath.Join(o.inputPath, overridesDirName)
	if err := os.MkdirAll(extractPath, 0755); err != nil {
		return fmt.Errorf("create extract dir: %w", err)
	}

	if err := extractTarGz(filePath, extractPath); err != nil {
		return fmt.Errorf("extract overrides: %w", err)
	}

	o.logger.InfoContext(ctx, "extracted NVD overrides", "path", extractPath)
	return nil
}

func (o *Overrides) CVE(cveID string) map[string]interface{} {
	if !o.enabled {
		return nil
	}

	if !o.loaded {
		o.buildCache()
		o.loaded = true
	}

	return o.cache[cveID]
}

func (o *Overrides) CVEs() []string {
	if !o.enabled {
		return nil
	}

	if !o.loaded {
		o.buildCache()
		o.loaded = true
	}

	ids := make([]string, 0, len(o.cache))
	for id := range o.cache {
		ids = append(ids, id)
	}
	return ids
}

func (o *Overrides) buildCache() {
	o.cache = make(map[string]map[string]interface{})

	extractPath := filepath.Join(o.inputPath, overridesDirName)

	err := filepath.WalkDir(extractPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			return nil
		}

		base := filepath.Base(path)
		if !strings.HasPrefix(base, "CVE-") || !strings.HasSuffix(base, ".json") {
			return nil
		}

		cveID := strings.TrimSuffix(base, ".json")
		cveID = strings.ToUpper(cveID)

		data, err := os.ReadFile(path)
		if err != nil {
			o.logger.Warn("failed to read override file", "path", path, "error", err)
			return nil
		}

		var record map[string]interface{}
		if err := json.Unmarshal(data, &record); err != nil {
			o.logger.Warn("failed to parse override file", "path", path, "error", err)
			return nil
		}

		o.cache[cveID] = record
		return nil
	})

	if err != nil {
		o.logger.Warn("failed to walk override files", "error", err)
		return
	}

	o.logger.Info("loaded override cache", "count", len(o.cache))
}

func ApplyOverride(cveID string, record map[string]interface{}, override map[string]interface{}) (bool, map[string]interface{}) {
	if override == nil {
		return false, record
	}

	cveOverride, ok := override["cve"].(map[string]interface{})
	if !ok {
		return false, record
	}

	_, hasConfigurations := cveOverride["configurations"]
	if !hasConfigurations {
		return false, record
	}

	cveRecord, ok := record["cve"].(map[string]interface{})
	if !ok {
		return false, record
	}

	cveRecord["configurations"] = cveOverride["configurations"]

	if overrideRefs, ok := cveOverride["references"].([]interface{}); ok && len(overrideRefs) > 0 {
		existingRefs, ok := cveRecord["references"].([]interface{})
		if !ok {
			existingRefs = []interface{}{}
		}

		existingURLs := make(map[string]bool)
		for _, r := range existingRefs {
			if ref, ok := r.(map[string]interface{}); ok {
				if u, ok := ref["url"].(string); ok {
					existingURLs[u] = true
				}
			}
		}

		for _, r := range overrideRefs {
			if ref, ok := r.(map[string]interface{}); ok {
				if u, ok := ref["url"].(string); ok {
					if !existingURLs[u] {
						existingRefs = append(existingRefs, r)
						existingURLs[u] = true
					}
				}
			}
		}

		cveRecord["references"] = existingRefs
	}

	return true, record
}

func extractTarGz(srcPath, destPath string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destPath, filepath.Base(header.Name))

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			outFile, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}

	return nil
}
