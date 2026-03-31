package rocky

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const DefaultURL = "https://apollo.build.resf.org/api/v3/osv/"

type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

func init() {
	provider.Register("rocky", NewProvider)
}

func NewProvider(config provider.Config) (provider.Provider, error) {
	manager := NewManager(config)

	return &Provider{
		Base:    provider.NewBase(config),
		config:  config,
		manager: manager,
	}, nil
}

func (p *Provider) Name() string {
	return "rocky"
}

func (p *Provider) Tags() []string {
	return []string{"vulnerability", "rocky", "osv"}
}

func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting Rocky Linux provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

	records, urls, err := p.manager.GetAllAdvisories(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch Rocky Linux advisories: %w", err)
	}

	p.Logger().InfoContext(ctx, "fetched Rocky Linux advisories", "count", len(records))

	storageBackend, err := storage.New(storage.Config{
		Type: p.config.Storage.Type,
		Path: p.config.Storage.Path,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("initialize storage: %w", err)
	}
	defer func() {
		if closeErr := storageBackend.Close(ctx); closeErr != nil {
			p.Logger().ErrorContext(ctx, "failed to close storage", "error", closeErr)
		}
	}()

	count := 0
	for advisoryID, record := range records {
		normalizedID := strings.ToLower(advisoryID)
		envelope := &storage.Envelope{
			Schema:     "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
			Identifier: fmt.Sprintf("rocky:%s", normalizedID),
			Item:       record,
		}

		if err := storageBackend.Write(ctx, envelope); err != nil {
			p.Logger().WarnContext(ctx, "failed to write record", "advisory", advisoryID, "error", err)
			continue
		}
		count++
	}

	p.Logger().InfoContext(ctx, "wrote Rocky Linux records to storage", "count", count)

	return urls, count, nil
}
