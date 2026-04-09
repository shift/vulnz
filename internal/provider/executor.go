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
	maxParallel   int
	workspace     string
	storeType     string
	logger        *slog.Logger
	providerNames []string // optional filter for RunAll
}

// ExecutorConfig configures the executor behavior.
type ExecutorConfig struct {
	MaxParallel   int      // Maximum number of providers to run in parallel
	Workspace     string   // Root workspace directory
	StoreType     string   // Storage backend: "flat-file" (default) or "sqlite"
	ProviderNames []string // If non-empty, RunAll only executes these named providers
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
		maxParallel:   config.MaxParallel,
		workspace:     config.Workspace,
		storeType:     config.StoreType,
		providerNames: config.ProviderNames,
		logger:        logger,
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
// If ExecutorConfig.ProviderNames was set, only those named providers are run.
func (e *Executor) RunAll(ctx context.Context) ([]Result, error) {
	providers := List()
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers registered")
	}

	// Filter by configured provider names when specified.
	if len(e.providerNames) > 0 {
		allowed := make(map[string]struct{}, len(e.providerNames))
		for _, n := range e.providerNames {
			allowed[n] = struct{}{}
		}
		filtered := providers[:0]
		for _, n := range providers {
			if _, ok := allowed[n]; ok {
				filtered = append(filtered, n)
			}
		}
		providers = filtered
		if len(providers) == 0 {
			return nil, fmt.Errorf("no providers matched ProviderNames filter %v", e.providerNames)
		}
	}

	e.logger.Info("running all providers", "count", len(providers))
	return e.Run(ctx, providers)
}

// RunSummary holds aggregate statistics produced by Summarize.
// VulnCount is the total number of vulnerabilities across all successful providers.
// ProviderCount is the total number of providers that ran (successful or not).
type RunSummary struct {
	VulnCount     int // Total vulnerabilities processed across all successful providers
	ProviderCount int // Total number of providers that were executed
	SuccessCount  int // Number of providers that completed without error
	ErrorCount    int // Number of providers that returned an error
}

// Summarize computes aggregate statistics from a slice of Results.
// Populate Result counts from actual provider output so callers never see zero values.
func Summarize(results []Result) RunSummary {
	s := RunSummary{
		ProviderCount: len(results),
	}
	for _, r := range results {
		if r.Err == nil {
			s.VulnCount += r.Count
			s.SuccessCount++
		} else {
			s.ErrorCount++
		}
	}
	return s
}

// CollectErrors returns a slice of all non-nil provider errors from results.
// This allows callers to surface and act on individual provider failures even
// though Run itself returns a nil top-level error (by design, to allow partial success).
func CollectErrors(results []Result) []error {
	var errs []error
	for _, r := range results {
		if r.Err != nil {
			errs = append(errs, fmt.Errorf("provider %q: %w", r.Provider, r.Err))
		}
	}
	return errs
}

// HasErrors returns true if any result in the slice contains a non-nil error.
func HasErrors(results []Result) bool {
	for _, r := range results {
		if r.Err != nil {
			return true
		}
	}
	return false
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

	storeType := e.storeType
	if storeType == "" {
		storeType = "flat-file"
	}

	storagePath := filepath.Join(e.workspace, name, "storage")
	if storeType == "sqlite" {
		storagePath = filepath.Join(e.workspace, name, "storage", "results.db")
	}

	providerLogger := e.logger.With("provider", name)
	config := Config{
		Name:      name,
		Workspace: filepath.Join(e.workspace, name),
		Logger:    providerLogger,
		HTTP:      DefaultHTTPConfig(),
		Storage: StorageConfig{
			Type: storeType,
			Path: storagePath,
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
		"store":                e.storeType,
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
