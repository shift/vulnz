// Package euvd implements a provider for the EU Vulnerability Database (EUVD) by ENISA.
// This provider fetches exploited vulnerability records with rich metadata including
// CVSS scores, EPSS, product versions, vendors, and aliases for EU CRA compliance.
package euvd

import (
	"context"
	"fmt"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const (
	// ExploitedURL is the EUVD endpoint for latest exploited vulnerabilities.
	ExploitedURL = "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities"

	// SearchURL is the EUVD search endpoint with flexible filters.
	SearchURL = "https://euvdservices.enisa.europa.eu/api/search"

	// MaxPageSize is the maximum number of records per search request.
	MaxPageSize = 100

	// PollInterval is the delay between paginated requests to respect rate limits.
	PollInterval = 500 * time.Millisecond
)

// Provider implements the provider.Provider interface for EUVD exploited vulnerability data.
type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

// init registers the EUVD provider with the provider registry on package initialization.
func init() {
	provider.Register("euvd", NewProvider)
}

// NewProvider creates a new EUVD provider instance with the given configuration.
func NewProvider(config provider.Config) (provider.Provider, error) {
	manager := NewManager(config)

	return &Provider{
		Base:    provider.NewBase(config),
		config:  config,
		manager: manager,
	}, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "euvd"
}

// Tags returns classification tags for this provider.
func (p *Provider) Tags() []string {
	return []string{"vulnerability", "exploited", "euvd", "enisa", "eu-cra"}
}

// Update fetches all exploited vulnerabilities from the EUVD search API with pagination.
// Returns the URLs fetched and the count of vulnerabilities processed.
func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting EUVD provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

	records, urls, err := p.manager.GetAllExploited(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch EUVD exploited data: %w", err)
	}

	p.Logger().InfoContext(ctx, "fetched EUVD exploited records", "count", len(records))

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
	for euvdID, record := range records {
		envelope := &storage.Envelope{
			Schema:     "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
			Identifier: fmt.Sprintf("euvd:%s", euvdID),
			Item:       record,
		}

		if err := storageBackend.Write(ctx, envelope); err != nil {
			p.Logger().WarnContext(ctx, "failed to write record", "euvd_id", euvdID, "error", err)
			continue
		}
		count++
	}

	p.Logger().InfoContext(ctx, "wrote EUVD records to storage", "count", count)

	return urls, count, nil
}
