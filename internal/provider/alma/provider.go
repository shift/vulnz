package alma

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
)

const (
	DefaultRepoURL = "https://github.com/AlmaLinux/osv-database.git"
)

var defaultVersions = []int{8, 9, 10}

type Provider struct {
	*provider.Base
	config  provider.Config
	manager *Manager
}

func init() {
	provider.Register("alma", NewProvider)
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
	return "alma"
}

func (p *Provider) Tags() []string {
	return []string{"vulnerability", "alma", "osv"}
}

func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().InfoContext(ctx, "starting AlmaLinux provider update")

	if lastUpdated != nil {
		p.Logger().InfoContext(ctx, "last updated", "time", lastUpdated)
	} else {
		p.Logger().InfoContext(ctx, "first run - no previous update")
	}

	advisories, err := p.manager.Get(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch AlmaLinux advisories: %w", err)
	}

	p.Logger().InfoContext(ctx, "fetched AlmaLinux advisories", "count", len(advisories))

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
			Schema:     "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
			Identifier: identifier,
			Item:       advisory,
		}

		if err := storageBackend.Write(ctx, envelope); err != nil {
			p.Logger().WarnContext(ctx, "failed to write advisory", "id", identifier, "error", err)
			continue
		}
		count++
	}

	p.Logger().InfoContext(ctx, "wrote AlmaLinux advisories to storage", "count", count)

	return []string{DefaultRepoURL}, count, nil
}

func versionFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, part := range parts {
		if part == "advisories" && i+1 < len(parts) {
			dir := parts[i+1]
			if strings.HasPrefix(dir, "almalinux") {
				return strings.TrimPrefix(dir, "almalinux")
			}
		}
	}
	return ""
}
