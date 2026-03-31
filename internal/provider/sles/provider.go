package sles

import (
	"context"
	"fmt"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const (
	ovalURLTemplate  = "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.%s.xml.bz2"
	ovalFileNameFmt  = "suse.linux.enterprise.server.%s.xml.bz2"
	ovalDirName      = "oval"
	schemaURL        = "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json"
	defaultNamespace = "sles"
)

var defaultVersions = []string{"11", "12", "15"}

type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

func init() {
	provider.Register("sles", NewProvider)
}

func NewProvider(config provider.Config) (provider.Provider, error) {
	manager := NewManagerWithVersions(config, defaultVersions)

	return &Provider{
		Base:    provider.NewBase(config),
		config:  config,
		manager: manager,
	}, nil
}

func (p *Provider) Name() string {
	return "sles"
}

func (p *Provider) Tags() []string {
	return []string{"vulnerability", "sles", "rpm", "oval"}
}

func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting SLES provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

	advisories, err := p.manager.Get(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch SLES advisories: %w", err)
	}

	p.Logger().InfoContext(ctx, "fetched SLES advisories", "count", len(advisories))

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
	for identifier, advisory := range advisories {
		envelope := &storage.Envelope{
			Schema:     schemaURL,
			Identifier: identifier,
			Item:       advisory,
		}

		if err := storageBackend.Write(ctx, envelope); err != nil {
			p.Logger().WarnContext(ctx, "failed to write advisory", "id", identifier, "error", err)
			continue
		}
		count++
	}

	p.Logger().InfoContext(ctx, "wrote SLES advisories to storage", "count", count)

	return p.manager.URLs(), count, nil
}
