package provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Executor orchestrates provider execution with concurrency control.
// It manages parallel provider execution, collects results, and handles errors.
type Executor struct {
	maxParallel int
	workspace   string
	logger      *slog.Logger
}

// ExecutorConfig configures the executor behavior.
type ExecutorConfig struct {
	MaxParallel int    // Maximum number of providers to run in parallel
	Workspace   string // Root workspace directory
}

// Result represents the outcome of running a provider.
type Result struct {
	Provider string        // Provider name
	URLs     []string      // URLs fetched by the provider
	Count    int           // Number of vulnerabilities processed
	Err      error         // Error if the provider failed
	Duration time.Duration // Time taken to execute the provider
	Updated  bool          // Whether this was an incremental update
}

// NewExecutor creates a new Executor with the given configuration.
func NewExecutor(config ExecutorConfig, logger *slog.Logger) *Executor {
	if config.MaxParallel <= 0 {
		config.MaxParallel = 1
	}

	return &Executor{
		maxParallel: config.MaxParallel,
		workspace:   config.Workspace,
		logger:      logger,
	}
}

// Run executes the specified providers in parallel with concurrency control.
// Returns a slice of results, one for each provider.
func (e *Executor) Run(ctx context.Context, providers []string) ([]Result, error) {
	if len(providers) == 0 {
		e.logger.Info("no providers to run")
		return nil, nil
	}

	e.logger.Info("starting provider execution",
		"providers", len(providers),
		"max_parallel", e.maxParallel)

	// Create semaphore to limit concurrency
	sem := make(chan struct{}, e.maxParallel)

	var wg sync.WaitGroup
	resultsChan := make(chan Result, len(providers))

	// Launch goroutines for each provider
	for _, name := range providers {
		wg.Add(1)

		go func(providerName string) {
			defer wg.Done()

			// Acquire semaphore slot
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				resultsChan <- Result{
					Provider: providerName,
					Err:      ctx.Err(),
				}
				return
			}

			// Execute provider
			result := e.runProvider(ctx, providerName)
			resultsChan <- result
		}(name)
	}

	// Wait for all providers to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	var results []Result
	for result := range resultsChan {
		results = append(results, result)

		if result.Err != nil {
			e.logger.Error("provider failed",
				"provider", result.Provider,
				"error", result.Err,
				"duration", result.Duration)
		} else {
			e.logger.Info("provider completed",
				"provider", result.Provider,
				"count", result.Count,
				"urls", len(result.URLs),
				"duration", result.Duration)
		}
	}

	return results, nil
}

// RunAll executes all registered providers.
func (e *Executor) RunAll(ctx context.Context) ([]Result, error) {
	providers := List()
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers registered")
	}

	e.logger.Info("running all providers", "count", len(providers))
	return e.Run(ctx, providers)
}

// runProvider executes a single provider and captures the result.
func (e *Executor) runProvider(ctx context.Context, name string) Result {
	start := time.Now()
	result := Result{
		Provider: name,
	}

	// Get provider factory
	factory, ok := Get(name)
	if !ok {
		result.Err = fmt.Errorf("provider %q not registered", name)
		result.Duration = time.Since(start)
		return result
	}

	// Read last successful run timestamp from workspace state
	lastUpdated := e.readLastUpdated(name)
	if lastUpdated != nil {
		e.logger.Info("incremental update",
			"provider", name,
			"since", lastUpdated.Format(time.RFC3339))
	} else {
		e.logger.Info("full update (no previous state)", "provider", name)
	}

	// Create provider configuration
	providerLogger := e.logger.With("provider", name)
	config := Config{
		Name:      name,
		Workspace: filepath.Join(e.workspace, name),
		Logger:    providerLogger,
		HTTP:      DefaultHTTPConfig(),
		Storage: StorageConfig{
			Type: "flat-file",
			Path: filepath.Join(e.workspace, name, "storage"),
		},
	}

	// Create provider instance
	provider, err := factory(config)
	if err != nil {
		result.Err = fmt.Errorf("create provider: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	e.logger.Info("executing provider", "provider", name)

	// Run provider update with lastUpdated for incremental support
	urls, count, err := provider.Update(ctx, lastUpdated)
	result.URLs = urls
	result.Count = count
	result.Err = err
	result.Duration = time.Since(start)
	result.Updated = lastUpdated != nil

	// Update workspace state on success
	if err == nil {
		if stateErr := e.updateState(name, urls, count); stateErr != nil {
			e.logger.Warn("failed to update workspace state",
				"provider", name,
				"error", stateErr)
		}
	}

	return result
}

// readLastUpdated reads the last successful run timestamp from workspace metadata.
// Returns nil if no previous state exists.
func (e *Executor) readLastUpdated(name string) *time.Time {
	metadataPath := filepath.Join(e.workspace, name, "metadata.json")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil
	}

	var state struct {
		Timestamp time.Time `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}

	if state.Timestamp.IsZero() {
		return nil
	}

	return &state.Timestamp
}

// updateState writes the workspace metadata after a successful provider run.
func (e *Executor) updateState(name string, urls []string, count int) error {
	workspacePath := filepath.Join(e.workspace, name)
	metadataPath := filepath.Join(workspacePath, "metadata.json")
	tempPath := metadataPath + ".tmp"

	if err := os.MkdirAll(workspacePath, 0755); err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}

	state := map[string]interface{}{
		"provider":             name,
		"urls":                 urls,
		"store":                "flat-file",
		"timestamp":            time.Now().UTC(),
		"version":              1,
		"distribution_version": 1,
		"processor":            "vulnz",
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := os.Rename(tempPath, metadataPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}
