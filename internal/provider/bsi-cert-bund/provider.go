package bsicertbund

import (
	"context"
	"fmt"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const (
	DefaultIndexURL = "https://wid.cert-bund.de/.well-known/csaf/white/bsi-wid-white.json"
	SchemaURL       = "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json"
)

type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

func init() {
	provider.Register("bsi-cert-bund", NewProvider)
}

func NewProvider(config provider.Config) (provider.Provider, error) {
	manager := NewManagerWithURL(DefaultIndexURL, config)

	return &Provider{
		Base:    provider.NewBase(config),
		config:  config,
		manager: manager,
	}, nil
}

func (p *Provider) Name() string {
	return "bsi-cert-bund"
}

func (p *Provider) Tags() []string {
	return []string{"vulnerability", "bsi", "csaf", "eu-cra"}
}

func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting BSI CERT-Bund provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

	records, err := p.manager.Get(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch BSI CERT-Bund data: %w", err)
	}

	p.Logger().InfoContext(ctx, "fetched BSI CERT-Bund records", "count", len(records))

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
			Schema:     SchemaURL,
			Identifier: fmt.Sprintf("bsi-cert-bund:%s", vulnID),
			Item:       record,
		}

		if err := storageBackend.Write(ctx, envelope); err != nil {
			p.Logger().WarnContext(ctx, "failed to write record", "id", vulnID, "error", err)
			continue
		}
		count++
	}

	p.Logger().InfoContext(ctx, "wrote BSI CERT-Bund records to storage", "count", count)

	return p.manager.URLs(), count, nil
}
