// Package provider example demonstrates how to create a custom provider.
//
// This file serves as a template and reference implementation for creating
// new vulnerability data providers. Follow this pattern when implementing
// the 27+ providers for vulnz-go.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/shift/vulnz/internal/provider"
)

// ExampleProvider demonstrates a minimal provider implementation.
type ExampleProvider struct {
	*provider.Base
	// Add provider-specific fields here (e.g., API client, parser config)
}

// init registers the provider. This is called automatically when the package is imported.
func init() {
	provider.Register("example", NewExampleProvider)
}

// NewExampleProvider creates a new instance of the example provider.
func NewExampleProvider(config provider.Config) (provider.Provider, error) {
	// Validate configuration if needed
	if config.Name == "" {
		return nil, fmt.Errorf("provider name is required")
	}

	return &ExampleProvider{
		Base: provider.NewBase(config),
		// Initialize provider-specific fields here
	}, nil
}

// Name returns the provider identifier.
func (p *ExampleProvider) Name() string {
	return "example"
}

// Update implements the core provider logic.
// This method should:
// 1. Fetch vulnerability data from the source
// 2. Parse and transform the data
// 3. Write results to storage
// 4. Return URLs fetched, count of results, and any errors
func (p *ExampleProvider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	p.Logger().Info("starting update")

	// Check if this is an incremental update
	if lastUpdated != nil {
		p.Logger().Info("performing incremental update", "since", lastUpdated)
	} else {
		p.Logger().Info("performing full update")
	}

	// Step 1: Fetch data
	// In a real provider, you would:
	// - Make HTTP requests to download vulnerability data
	// - Save raw data to the workspace input directory
	// - Handle rate limiting, retries, and errors
	urls := []string{
		"https://example.com/vulnerabilities.json",
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return urls, 0, err
	}

	// Step 2: Parse data
	// In a real provider, you would:
	// - Read files from workspace input directory
	// - Parse JSON/XML/CSV/etc.
	// - Transform to standard vulnerability schema

	// Step 3: Write results
	// In a real provider, you would:
	// - Create result envelopes
	// - Write to storage backend
	// - Track count of vulnerabilities processed
	count := 100 // Example count

	p.Logger().Info("update completed", "count", count, "urls", len(urls))

	return urls, count, nil
}

// Metadata implements the MetadataProvider interface (optional).
func (p *ExampleProvider) Metadata() provider.Metadata {
	return provider.Metadata{
		Name:        "example",
		Description: "Example vulnerability data provider",
		Version:     "1.0.0",
		Homepage:    "https://github.com/shift/vulnz",
	}
}

// Tags implements the TagsProvider interface (optional).
func (p *ExampleProvider) Tags() []string {
	return []string{"example", "demo"}
}

// Example usage of the provider framework
func main() {
	// Create a logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Example 1: Create and run a single provider
	fmt.Println("=== Example 1: Single Provider ===")
	runSingleProvider(logger)

	// Example 2: Run multiple providers in parallel
	fmt.Println("\n=== Example 2: Multiple Providers ===")
	runMultipleProviders(logger)

	// Example 3: List all registered providers
	fmt.Println("\n=== Example 3: List Providers ===")
	listProviders()
}

func runSingleProvider(logger *slog.Logger) {
	// Import the provider package to trigger registration
	// In a real application, you would import specific provider packages:
	// import _ "github.com/shift/vulnz/providers/alpine"
	// import _ "github.com/shift/vulnz/providers/debian"

	config := provider.Config{
		Name:      "example",
		Workspace: "/tmp/vulnz-data/example",
		Logger:    logger.With("provider", "example"),
		HTTP:      provider.DefaultHTTPConfig(),
	}

	// Create provider instance
	p, err := NewExampleProvider(config)
	if err != nil {
		logger.Error("failed to create provider", "error", err)
		return
	}

	// Run the provider
	ctx := context.Background()
	urls, count, err := p.Update(ctx, nil)
	if err != nil {
		logger.Error("provider failed", "error", err)
		return
	}

	fmt.Printf("Provider completed: %d vulnerabilities from %d URLs\n", count, len(urls))
}

func runMultipleProviders(logger *slog.Logger) {
	// Create executor with concurrency control
	executor := provider.NewExecutor(provider.ExecutorConfig{
		MaxParallel: 4,
		Workspace:   "/tmp/vulnz-data",
	}, logger)

	// Run specific providers
	ctx := context.Background()
	results, err := executor.Run(ctx, []string{"example"})
	if err != nil {
		logger.Error("executor failed", "error", err)
		return
	}

	// Process results
	for _, result := range results {
		if result.Err != nil {
			fmt.Printf("❌ %s failed: %v\n", result.Provider, result.Err)
		} else {
			fmt.Printf("✓ %s completed: %d vulnerabilities in %v\n",
				result.Provider, result.Count, result.Duration)
		}
	}
}

func listProviders() {
	providers := provider.List()
	fmt.Printf("Registered providers: %d\n", len(providers))
	for i, name := range providers {
		fmt.Printf("  %d. %s\n", i+1, name)
	}
}
