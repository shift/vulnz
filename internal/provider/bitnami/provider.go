package bitnami

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const (
	DefaultRepoURL = "https://github.com/bitnami/vulndb.git"
	RepoBranch     = "main"
)

type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

func init() {
	provider.Register("bitnami", NewProvider)
}

func NewProvider(config provider.Config) (provider.Provider, error) {
	manager := NewManager(DefaultRepoURL, config)

	return &Provider{
		Base:    provider.NewBase(config),
		config:  config,
		manager: manager,
	}, nil
}

func (p *Provider) Name() string {
	return "bitnami"
}

func (p *Provider) Tags() []string {
	return []string{"vulnerability", "bitnami", "osv"}
}

func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting bitnami provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

	if err := p.manager.CloneRepo(ctx); err != nil {
		return nil, 0, fmt.Errorf("clone bitnami vulndb: %w", err)
	}

	records, err := p.manager.WalkAdvisories()
	if err != nil {
		return nil, 0, fmt.Errorf("walk bitnami advisories: %w", err)
	}

	p.Logger().InfoContext(ctx, "found bitnami advisories", "count", len(records))

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
		envelope := &storage.Envelope{
			Schema:     "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
			Identifier: fmt.Sprintf("bitnami:%s", strings.ToLower(advisoryID)),
			Item:       record,
		}

		if err := storageBackend.Write(ctx, envelope); err != nil {
			p.Logger().WarnContext(ctx, "failed to write record", "id", advisoryID, "error", err)
			continue
		}
		count++
	}

	p.Logger().InfoContext(ctx, "wrote bitnami records to storage", "count", count)

	return []string{DefaultRepoURL}, count, nil
}
