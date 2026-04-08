package api

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/shift/vulnz/internal/provider"
	_ "github.com/shift/vulnz/internal/providers"
	"github.com/shift/vulnz/internal/storage"
)

type IngestOptions struct {
	WorkspacePath string
	Providers     []string
}

func Ingest(ctx context.Context, opts IngestOptions) error {
	if opts.WorkspacePath == "" {
		return fmt.Errorf("vulnz/api: WorkspacePath must not be empty")
	}

	providerNames := opts.Providers
	if len(providerNames) == 0 {
		providerNames = provider.List()
		if len(providerNames) == 0 {
			return fmt.Errorf("vulnz/api: no providers registered")
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	exec := provider.NewExecutor(provider.ExecutorConfig{
		MaxParallel: 4,
		Workspace:   opts.WorkspacePath,
	}, logger)

	results, err := exec.Run(ctx, providerNames)
	if err != nil {
		return fmt.Errorf("vulnz/api: executor: %w", err)
	}

	for _, r := range results {
		if r.Err != nil {
			return fmt.Errorf("vulnz/api: provider %q: %w", r.Provider, r.Err)
		}
	}

	return nil
}

func FetchEUFeeds(ctx context.Context, providers []string) ([]FetchResult, error) {
	if len(providers) == 0 {
		providers = []string{"euvd", "bsi-cert-bund", "kev"}
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	results := make([]FetchResult, 0, len(providers))

	for _, name := range providers {
		fetchResult, err := fetchProvider(ctx, name, logger)
		if err != nil {
			return results, fmt.Errorf("vulnz/api: provider %q: %w", name, err)
		}
		results = append(results, fetchResult)
	}

	return results, nil
}

func fetchProvider(ctx context.Context, name string, logger *slog.Logger) (FetchResult, error) {
	factory, ok := provider.Get(name)
	if !ok {
		return FetchResult{}, fmt.Errorf("provider %q not registered", name)
	}

	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("vulnz-api-%s-", name))
	if err != nil {
		return FetchResult{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	storagePath := filepath.Join(tmpDir, "storage")

	config := provider.Config{
		Name:      name,
		Workspace: tmpDir,
		Logger:    logger.With("provider", name),
		HTTP:      provider.DefaultHTTPConfig(),
		Storage: provider.StorageConfig{
			Type: "sqlite",
			Path: filepath.Join(storagePath, "results.db"),
		},
	}

	prov, err := factory(config)
	if err != nil {
		return FetchResult{}, fmt.Errorf("create provider: %w", err)
	}

	_, _, err = prov.Update(ctx, nil)
	if err != nil {
		return FetchResult{}, fmt.Errorf("update: %w", err)
	}

	backend, err := storage.New(storage.Config{
		Type: "sqlite",
		Path: filepath.Join(storagePath, "results.db"),
	})
	if err != nil {
		return FetchResult{}, fmt.Errorf("open storage: %w", err)
	}
	defer backend.Close(ctx)

	ids, err := backend.List(ctx)
	if err != nil {
		return FetchResult{}, fmt.Errorf("list records: %w", err)
	}

	records := make([]FeedRecord, 0, len(ids))
	for _, id := range ids {
		envelope, err := backend.Read(ctx, id)
		if err != nil {
			logger.Warn("failed to read record", "id", id, "error", err)
			continue
		}

		item, ok := envelope.Item.(map[string]interface{})
		if !ok {
			logger.Warn("record item is not a map", "id", id)
			continue
		}

		record := convertEnvelope(name, id, item)
		records = append(records, record)
	}

	return FetchResult{
		Provider: name,
		Records:  records,
		Count:    len(records),
	}, nil
}

func convertEnvelope(providerName, id string, item map[string]interface{}) FeedRecord {
	rec := FeedRecord{
		Provider: providerName,
	}

	switch providerName {
	case "kev":
		rec = convertKEV(id, item)
	case "euvd":
		rec = convertEUVD(id, item)
	case "bsi-cert-bund":
		rec = convertBSI(id, item)
	default:
		rec.Cve = id
	}

	return rec
}

func convertKEV(id string, item map[string]interface{}) FeedRecord {
	rec := FeedRecord{Provider: "kev"}

	cveID, _ := item["cveId"].(string)
	if cveID == "" {
		cveID = id
	}
	rec.Cve = cveID

	exploitedInWild, _ := item["exploited_in_wild"].(bool)
	rec.KevExploited = exploitedInWild

	if dateAddedStr, ok := item["dateAdded"].(string); ok && dateAddedStr != "" {
		if t, err := time.Parse("2006-01-02", dateAddedStr); err == nil {
			rec.KevDateAdded = &t
		}
	}

	product := toString(item["product"])
	vendor := toString(item["vendorProject"])
	if product != "" {
		rec.AffectedProducts = []AffectedProduct{
			{Name: product, Vendor: vendor},
		}
	}

	return rec
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func convertEUVD(id string, item map[string]interface{}) FeedRecord {
	rec := FeedRecord{Provider: "euvd"}

	euvdID, _ := item["euvdId"].(string)
	rec.EnisaEuvdID = euvdID

	cveID := ""
	if cveIdsRaw, ok := item["cveIds"].([]interface{}); ok && len(cveIdsRaw) > 0 {
		if s, ok := cveIdsRaw[0].(string); ok {
			cveID = s
		}
	}
	if cveID == "" {
		cveID = euvdID
	}
	if cveID == "" {
		cveID = id
	}
	rec.Cve = cveID

	if baseScore, ok := item["baseScore"].(float64); ok {
		switch {
		case baseScore >= 9.0:
			rec.EnisaSeverity = "Critical"
		case baseScore >= 7.0:
			rec.EnisaSeverity = "High"
		case baseScore >= 4.0:
			rec.EnisaSeverity = "Medium"
		default:
			rec.EnisaSeverity = "Low"
		}
	}

	if meta, ok := item["metadata"].(map[string]interface{}); ok {
		if s, ok := meta["severity"].(string); ok && s != "" {
			rec.EnisaSeverity = s
		}
	}

	if productsRaw, ok := item["affectedProducts"].([]interface{}); ok {
		var aps []AffectedProduct
		for _, pRaw := range productsRaw {
			p, ok := pRaw.(map[string]interface{})
			if !ok {
				continue
			}
			ap := AffectedProduct{
				Name:    toString(p["name"]),
				Version: toString(p["version"]),
			}
			aps = append(aps, ap)
		}
		rec.AffectedProducts = aps
	}

	if vendorsRaw, ok := item["vendors"].([]interface{}); ok {
		for i, vRaw := range vendorsRaw {
			if i < len(rec.AffectedProducts) {
				if v, ok := vRaw.(string); ok {
					rec.AffectedProducts[i].Vendor = v
				}
			}
		}
	}

	return rec
}

func convertBSI(id string, item map[string]interface{}) FeedRecord {
	rec := FeedRecord{Provider: "bsi-cert-bund"}

	advisoryID := ""
	cveID := ""
	var tr03116Compliant *bool

	if meta, ok := item["metadata"].(map[string]interface{}); ok {
		if v, ok := meta["advisory_id"].(string); ok {
			advisoryID = v
		}
		if v, ok := meta["cve_id"].(string); ok {
			cveID = v
		}
		if v, ok := meta["bsi_tr_03116_compliant"].(bool); ok {
			tr03116Compliant = &v
		}
	}

	if cveID == "" {
		cveID = id
	}

	if advisoryID == "" {
		if advisoriesRaw, ok := item["advisories"].([]interface{}); ok && len(advisoriesRaw) > 0 {
			if first, ok := advisoriesRaw[0].(map[string]interface{}); ok {
				if v, ok := first["id"].(string); ok {
					advisoryID = v
				}
			}
		}
	}

	rec.Cve = cveID
	rec.BsiAdvisoryID = advisoryID
	rec.BsiTr03116Compliant = tr03116Compliant

	if affectedRaw, ok := item["affected"].([]interface{}); ok {
		var aps []AffectedProduct
		for _, aRaw := range affectedRaw {
			a, ok := aRaw.(map[string]interface{})
			if !ok {
				continue
			}
			ap := AffectedProduct{
				Name:    toString(a["name"]),
				Vendor:  toString(a["vendor"]),
				Version: toString(a["version"]),
			}
			aps = append(aps, ap)
		}
		rec.AffectedProducts = aps
	}

	return rec
}
