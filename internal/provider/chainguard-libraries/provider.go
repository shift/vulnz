package chainguardlibraries

import (
	"context"
	"fmt"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const (
	DefaultIndexURL = "https://libraries.cgr.dev/openvex/v1/all.json"
)

type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

func init() {
	provider.Register("chainguard-libraries", NewProvider)
}

func NewProvider(config provider.Config) (provider.Provider, error) {
	manager := NewManager(DefaultIndexURL, config)

	return &Provider{
		Base:    provider.NewBase(config),
		config:  config,
		manager: manager,
	}, nil
}

func (p *Provider) Name() string {
	return "chainguard-libraries"
}

func (p *Provider) Tags() []string {
	return []string{"vulnerability", "chainguard", "openvex", "pypi"}
}

func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting chainguard-libraries provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

	records, err := p.manager.Get(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch chainguard-libraries data: %w", err)
	}

	p.Logger().InfoContext(ctx, "fetched chainguard-libraries records", "count", len(records))

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
			Schema:     "https://openvex.dev/ns/v0.2.0",
			Identifier: fmt.Sprintf("chainguard-libraries:pypi:%s", vulnID),
			Item:       record,
		}

		if err := storageBackend.Write(ctx, envelope); err != nil {
			p.Logger().WarnContext(ctx, "failed to write record", "vulnerability", vulnID, "error", err)
			continue
		}
		count++
	}

	p.Logger().InfoContext(ctx, "wrote chainguard-libraries records to storage", "count", count)

	return p.manager.URLs(), count, nil
}
