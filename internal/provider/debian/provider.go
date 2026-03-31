package debian

import (
	"context"
	"fmt"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const (
	DefaultJSONURL = "https://security-tracker.debian.org/tracker/data/json"
	DefaultDSAURL  = "https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/DSA/list"
	SchemaURL      = "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json"
)

type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

func init() {
	provider.Register("debian", NewProvider)
}

func NewProvider(config provider.Config) (provider.Provider, error) {
	manager := NewManager(DefaultJSONURL, DefaultDSAURL, config)

	return &Provider{
		Base:    provider.NewBase(config),
		config:  config,
		manager: manager,
	}, nil
}

func (p *Provider) Name() string {
	return "debian"
}

func (p *Provider) Tags() []string {
	return []string{"vulnerability", "debian", "dpkg"}
}

func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting Debian provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

	records, err := p.manager.Get(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch Debian data: %w", err)
	}

	p.Logger().InfoContext(ctx, "fetched Debian records", "count", len(records))

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
	for _, record := range records {
		vulnName := record.Name
		namespace := record.NamespaceName

		identifier := fmt.Sprintf("%s:%s", namespace, vulnName)

		envelope := &storage.Envelope{
			Schema:     SchemaURL,
			Identifier: identifier,
			Item:       record.ToPayload(),
		}

		if err := storageBackend.Write(ctx, envelope); err != nil {
			p.Logger().WarnContext(ctx, "failed to write record", "cve", vulnName, "error", err)
			continue
		}
		count++
	}

	p.Logger().InfoContext(ctx, "wrote Debian records to storage", "count", count)

	return p.manager.URLs(), count, nil
}
