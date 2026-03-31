// Package kev implements a provider for the consolidated Known Exploited Vulnerabilities catalog.
// This provider fetches actively exploited vulnerabilities from the EUVD (EU Vulnerability Database)
// consolidated KEV dump, which merges CISA KEV and EU KEV sources for EU CRA compliance.
package kev

import (
	"context"
	"fmt"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const (
	// DefaultURL is the EUVD consolidated KEV dump endpoint (CISA KEV + EU KEV).
	// Updated daily at 07:00 UTC. Supersedes the CISA-only feed.
	DefaultURL = "https://euvdservices.enisa.europa.eu/api/kev/dump"
)

// Provider implements the provider.Provider interface for KEV data.
type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

// init registers the KEV provider with the provider registry on package initialization.
func init() {
	provider.Register("kev", NewProvider)
}

// NewProvider creates a new KEV provider instance with the given configuration.
func NewProvider(config provider.Config) (provider.Provider, error) {
	manager := NewManager(DefaultURL, config)

	return &Provider{
		Base:    provider.NewBase(config),
		config:  config,
		manager: manager,
	}, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "kev"
}

// Tags returns classification tags for this provider.
func (p *Provider) Tags() []string {
	return []string{"auxiliary", "exploited", "euvd", "eu-cra"}
}

// Update fetches and processes KEV data from the EUVD consolidated dump.
// Returns the URLs fetched and the count of vulnerabilities processed.
func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting KEV provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

	records, err := p.manager.Get(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch KEV data: %w", err)
	}

	p.Logger().InfoContext(ctx, "fetched KEV records", "count", len(records))

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
	for cveID, record := range records {
		envelope := &storage.Envelope{
			Schema:     "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
			Identifier: fmt.Sprintf("kev:%s", cveID),
			Item:       record,
		}

		if err := storageBackend.Write(ctx, envelope); err != nil {
			p.Logger().WarnContext(ctx, "failed to write record", "cve", cveID, "error", err)
			continue
		}
		count++
	}

	p.Logger().InfoContext(ctx, "wrote KEV records to storage", "count", count)

	return p.manager.URLs(), count, nil
}
