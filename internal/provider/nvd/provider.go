package nvd

import (
	"context"
	"fmt"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const (
	SchemaURL = "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/nvd/schema-1.0.0.json"
)

type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

func init() {
	provider.Register("nvd", NewProvider)
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
	return "nvd"
}

func (p *Provider) Tags() []string {
	return []string{"vulnerability", "incremental", "large"}
}

func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting nvd provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

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

	count, err := p.manager.GetStream(ctx, lastUpdated, storageBackend)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch NVD data: %w", err)
	}

	p.Logger().InfoContext(ctx, "wrote NVD records to storage", "count", count)

	return p.manager.URLs(), count, nil
}
