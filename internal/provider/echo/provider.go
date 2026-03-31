// Package echo provides a test provider with mock vulnerability data
// for validating the vulnz-go framework integration.
package echo

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/storage"
	"github.com/shift/vulnz/internal/workspace"
)

const (
	// SchemaVersion is the Echo provider schema version
	SchemaVersion = "1.0"
	// Release is the default release name for Echo
	Release = "rolling"
)

// Provider implements the provider.Provider interface for Echo test data.
type Provider struct {
	*provider.Base
	config       Config
	parser       *Parser
	workspaceMgr *workspace.Manager
}

// init registers the echo provider with the provider registry.
func init() {
	provider.Register("echo", NewProvider)
}

// NewProvider creates a new Echo provider instance.
func NewProvider(providerConfig provider.Config) (provider.Provider, error) {
	// Get Echo-specific configuration or use defaults
	config := DefaultConfig()
	config.Provider = providerConfig

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: config.RequestTimeout,
	}

	// Create workspace manager
	workspaceMgr := workspace.NewManager(providerConfig.Workspace)

	// Initialize workspace
	if err := workspaceMgr.Initialize(providerConfig.Name); err != nil {
		return nil, fmt.Errorf("initialize workspace: %w", err)
	}

	// Create parser
	inputPath := workspaceMgr.GetInputPath(providerConfig.Name)
	parser := NewParser(config.URL, config.Namespace, inputPath, httpClient)

	return &Provider{
		Base:         provider.NewBase(providerConfig),
		config:       config,
		parser:       parser,
		workspaceMgr: workspaceMgr,
	}, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "echo"
}

// Update fetches and processes Echo vulnerability data.
func (p *Provider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().Info("starting echo provider update")

	if lastUpdated != nil {
		p.Logger().Info("last updated", "time", lastUpdated)
	} else {
		p.Logger().Info("first run - no previous update")
	}

	// Fetch and parse vulnerability data
	vulns, err := p.parser.Get(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch vulnerabilities: %w", err)
	}

	p.Logger().Info("fetched vulnerabilities", "count", len(vulns))

	// Create storage backend
	resultsPath := p.workspaceMgr.GetResultsPath(p.Name())
	backend, err := storage.New(storage.Config{
		Type: p.Config().Storage.Type,
		Path: resultsPath,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("create storage backend: %w", err)
	}
	defer backend.Close(ctx)

	// Write vulnerability records to storage
	count := 0
	for vulnID, vuln := range vulns {
		// Create identifier with namespace prefix
		identifier := fmt.Sprintf("%s:%s:%s", p.config.Namespace, Release, vulnID)

		// Create envelope with vulnerability payload
		envelope := &storage.Envelope{
			Schema:     fmt.Sprintf("https://schema.anchore.io/vulnerability/%s", SchemaVersion),
			Identifier: identifier,
			Item:       vuln.ToPayload(),
		}

		if err := backend.Write(ctx, envelope); err != nil {
			return nil, 0, fmt.Errorf("write vulnerability %s: %w", vulnID, err)
		}
		count++
	}

	p.Logger().Info("wrote vulnerability records", "count", count)

	// Update workspace state
	state := &workspace.State{
		Provider:            p.Name(),
		URLs:                []string{p.config.URL},
		Store:               p.Config().Storage.Type,
		Timestamp:           time.Now(),
		Version:             1,
		DistributionVersion: 1,
		Stale:               false,
		Processor:           "vulnz-go",
	}

	if err := p.workspaceMgr.UpdateState(p.Name(), state); err != nil {
		return nil, 0, fmt.Errorf("update workspace state: %w", err)
	}

	return []string{p.config.URL}, count, nil
}

// Metadata returns provider metadata.
func (p *Provider) Metadata() provider.Metadata {
	return provider.Metadata{
		Name:        "echo",
		Description: "Test provider with mock vulnerability data for framework validation",
		Version:     "1.0.0",
		Homepage:    "https://github.com/shift/vulnz",
	}
}

// Tags returns provider classification tags.
func (p *Provider) Tags() []string {
	return []string{"vulnerability", "os", "test"}
}
