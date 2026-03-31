package secureos

import (
	"context"
	"fmt"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const (
	DefaultURL = "https://security.secureos.io/v1/latest.json"
	Namespace  = "secureos:rolling"
)

type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

func init() {
	provider.Register("secureos", NewProvider)
}

func NewProvider(config provider.Config) (provider.Provider, error) {
	manager := NewManager(DefaultURL, config)

	return &Provider{
		Base:    provider.NewBase(config),
		config:  config,
		manager: manager,
	}, nil
}

func (p *Provider) Name() string {
	return "secureos"
}

func (p *Provider) Tags() []string {
	return []string{"vulnerability", "secureos", "apk"}
}

func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting secureos provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

	records, err := p.manager.Get(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch secureos data: %w", err)
	}

	p.Logger().InfoContext(ctx, "fetched secureos records", "count", len(records))

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
	for vulnID, record := range records {
		envelope := &storage.Envelope{
			Schema:     "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
			Identifier: fmt.Sprintf("secureos:rolling:%s", vulnID),
			Item:       record,
		}

		if err := storageBackend.Write(ctx, envelope); err != nil {
			p.Logger().WarnContext(ctx, "failed to write record", "vulnerability", vulnID, "error", err)
			continue
		}
		count++
	}

	p.Logger().InfoContext(ctx, "wrote secureos records to storage", "count", count)

	return p.manager.URLs(), count, nil
}
