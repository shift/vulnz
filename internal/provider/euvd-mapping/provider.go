// Package euvdmapping implements a provider for the CVE-to-EUVD ID mapping from ENISA.
// This provider fetches the daily-updated CSV mapping between CVE identifiers and
// EU Vulnerability Database (EUVD) identifiers for cross-referencing.
package euvdmapping

import (
	"context"
	"fmt"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const (
	// DefaultURL is the EUVD CVE-to-EUVD mapping CSV dump endpoint.
	// Updated daily at 07:00 UTC.
	DefaultURL = "https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping"
)

// Provider implements the provider.Provider interface for CVE-EUVD ID mapping data.
type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

// init registers the EUVD mapping provider with the provider registry on package initialization.
func init() {
	provider.Register("euvd-mapping", NewProvider)
}

// NewProvider creates a new EUVD mapping provider instance with the given configuration.
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
	return "euvd-mapping"
}

// Tags returns classification tags for this provider.
func (p *Provider) Tags() []string {
	return []string{"auxiliary", "mapping", "euvd", "enisa"}
}

// Update fetches and processes the CVE-EUVD ID mapping from ENISA.
// Returns the URLs fetched and the count of mappings processed.
func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting EUVD mapping provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

	mappings, err := p.manager.Get(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch EUVD mapping: %w", err)
	}

	p.Logger().InfoContext(ctx, "fetched EUVD mappings", "count", len(mappings))

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

	// Write the complete mapping as a single record
	envelope := &storage.Envelope{
		Schema:     "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
		Identifier: "euvd-mapping:full",
		Item: map[string]interface{}{
			"total_mappings": len(mappings),
			"mappings":       mappings,
			"namespace":      "euvd-mapping",
			"metadata": map[string]interface{}{
				"source":        "euvd-cve-mapping",
				"format":        "csv",
				"updated_daily": true,
			},
		},
	}

	if err := storageBackend.Write(ctx, envelope); err != nil {
		return nil, 0, fmt.Errorf("write mapping to storage: %w", err)
	}

	p.Logger().InfoContext(ctx, "wrote EUVD mappings to storage", "count", len(mappings))

	return p.manager.URLs(), len(mappings), nil
}
