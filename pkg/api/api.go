// Package api provides a thin exported interface for consuming vulnz as a library.
// It wraps the internal provider executor so external packages can trigger
// vulnerability data ingestion without depending on internal packages directly.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/shift/vulnz/internal/provider"
	_ "github.com/shift/vulnz/internal/providers" // side-effect: registers all providers
)

// IngestOptions configures a call to Ingest.
type IngestOptions struct {
	// WorkspacePath is the root directory where provider data will be written.
	// The directory will be created if it does not exist.
	WorkspacePath string

	// Providers is the list of provider names to run.
	// If empty, all registered providers are run.
	Providers []string
}

// Ingest runs the requested vulnerability-data providers and writes results
// to the workspace.  It mirrors the behaviour of `vulnz run` at the CLI level:
//
//   - blank-importing this package's providers side-effect registers all built-in
//     providers automatically.
//   - If opts.Providers is empty every registered provider is run.
//   - If any provider returns an error it is collected; the function returns the
//     first non-nil provider error encountered after all providers have run.
func Ingest(ctx context.Context, opts IngestOptions) error {
	if opts.WorkspacePath == "" {
		return fmt.Errorf("vulnz/api: WorkspacePath must not be empty")
	}

	// Resolve which providers to run.
	providerNames := opts.Providers
	if len(providerNames) == 0 {
		providerNames = provider.List()
		if len(providerNames) == 0 {
			return fmt.Errorf("vulnz/api: no providers registered")
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	exec := provider.NewExecutor(provider.ExecutorConfig{
		MaxParallel: 4,
		Workspace:   opts.WorkspacePath,
	}, logger)

	results, err := exec.Run(ctx, providerNames)
	if err != nil {
		return fmt.Errorf("vulnz/api: executor: %w", err)
	}

	// Surface the first provider-level error.
	for _, r := range results {
		if r.Err != nil {
			return fmt.Errorf("vulnz/api: provider %q: %w", r.Provider, r.Err)
		}
	}

	return nil
}
