package provider

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"
)

// mockProvider is a mock provider for testing.
type mockProvider struct {
	name        string
	updateFunc  func(ctx context.Context, lastUpdated *time.Time) ([]string, int, error)
	callCount   int
	lastContext context.Context
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	m.callCount++
	m.lastContext = ctx

	if m.updateFunc != nil {
		return m.updateFunc(ctx, lastUpdated)
	}

	return []string{}, 0, nil
}

// TestExecutor_Run tests running multiple providers.
func TestExecutor_Run(t *testing.T) {
	Reset()

	// Create mock providers
	provider1 := &mockProvider{name: "provider1"}
	provider2 := &mockProvider{name: "provider2"}
	provider3 := &mockProvider{name: "provider3"}

	Register("provider1", func(config Config) (Provider, error) {
		return provider1, nil
	})
	Register("provider2", func(config Config) (Provider, error) {
		return provider2, nil
	})
	Register("provider3", func(config Config) (Provider, error) {
		return provider3, nil
	})

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	executor := NewExecutor(ExecutorConfig{
		MaxParallel: 2,
		Workspace:   t.TempDir(),
	}, logger)

	ctx := context.Background()
	results, err := executor.Run(ctx, []string{"provider1", "provider2", "provider3"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Verify all providers were called
	if provider1.callCount != 1 {
		t.Errorf("expected provider1 to be called once, got %d", provider1.callCount)
	}
	if provider2.callCount != 1 {
		t.Errorf("expected provider2 to be called once, got %d", provider2.callCount)
	}
	if provider3.callCount != 1 {
		t.Errorf("expected provider3 to be called once, got %d", provider3.callCount)
	}

	// Verify results
	for _, result := range results {
		if result.Err != nil {
			t.Errorf("provider %s failed: %v", result.Provider, result.Err)
		}
		if result.Duration == 0 {
			t.Errorf("provider %s has zero duration", result.Provider)
		}
	}
}

// TestExecutor_RunWithErrors tests handling provider errors.
func TestExecutor_RunWithErrors(t *testing.T) {
	Reset()

	expectedErr := errors.New("test error")

	successProvider := &mockProvider{name: "success"}
	errorProvider := &mockProvider{
		name: "error",
		updateFunc: func(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
			return nil, 0, expectedErr
		},
	}

	Register("success", func(config Config) (Provider, error) {
		return successProvider, nil
	})
	Register("error", func(config Config) (Provider, error) {
		return errorProvider, nil
	})

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	executor := NewExecutor(ExecutorConfig{
		MaxParallel: 2,
		Workspace:   t.TempDir(),
	}, logger)

	ctx := context.Background()
	results, err := executor.Run(ctx, []string{"success", "error"})

	if err != nil {
		t.Fatalf("unexpected executor error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Find the error result
	var errorResult *Result
	for i := range results {
		if results[i].Provider == "error" {
			errorResult = &results[i]
			break
		}
	}

	if errorResult == nil {
		t.Fatal("expected error result not found")
	}

	if errorResult.Err == nil {
		t.Error("expected error result to have error")
	}

	if !errors.Is(errorResult.Err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, errorResult.Err)
	}
}

// TestExecutor_RunWithContext tests context cancellation.
func TestExecutor_RunWithContext(t *testing.T) {
	Reset()

	slowProvider := &mockProvider{
		name: "slow",
		updateFunc: func(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
			select {
			case <-time.After(5 * time.Second):
				return []string{}, 0, nil
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			}
		},
	}

	Register("slow", func(config Config) (Provider, error) {
		return slowProvider, nil
	})

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	executor := NewExecutor(ExecutorConfig{
		MaxParallel: 1,
		Workspace:   t.TempDir(),
	}, logger)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	results, err := executor.Run(ctx, []string{"slow"})

	if err != nil {
		t.Fatalf("unexpected executor error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Err == nil {
		t.Error("expected provider to fail due to context cancellation")
	}

	if !errors.Is(results[0].Err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", results[0].Err)
	}
}

// TestExecutor_RunAll tests running all registered providers.
func TestExecutor_RunAll(t *testing.T) {
	Reset()

	provider1 := &mockProvider{name: "provider1"}
	provider2 := &mockProvider{name: "provider2"}

	Register("provider1", func(config Config) (Provider, error) {
		return provider1, nil
	})
	Register("provider2", func(config Config) (Provider, error) {
		return provider2, nil
	})

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	executor := NewExecutor(ExecutorConfig{
		MaxParallel: 2,
		Workspace:   t.TempDir(),
	}, logger)

	ctx := context.Background()
	results, err := executor.RunAll(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	if provider1.callCount != 1 {
		t.Errorf("expected provider1 to be called once, got %d", provider1.callCount)
	}
	if provider2.callCount != 1 {
		t.Errorf("expected provider2 to be called once, got %d", provider2.callCount)
	}
}

// TestExecutor_RunAllEmpty tests RunAll with no registered providers.
func TestExecutor_RunAllEmpty(t *testing.T) {
	Reset()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	executor := NewExecutor(ExecutorConfig{
		MaxParallel: 2,
		Workspace:   t.TempDir(),
	}, logger)

	ctx := context.Background()
	results, err := executor.RunAll(ctx)

	if err == nil {
		t.Error("expected error when no providers registered")
	}

	if results != nil {
		t.Errorf("expected nil results, got %v", results)
	}
}

// TestExecutor_RunEmpty tests Run with empty provider list.
func TestExecutor_RunEmpty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	executor := NewExecutor(ExecutorConfig{
		MaxParallel: 2,
		Workspace:   t.TempDir(),
	}, logger)

	ctx := context.Background()
	results, err := executor.Run(ctx, []string{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if results != nil {
		t.Errorf("expected nil results for empty provider list, got %v", results)
	}
}

// TestExecutor_ConcurrencyLimit tests that concurrency is properly limited.
func TestExecutor_ConcurrencyLimit(t *testing.T) {
	Reset()

	const maxParallel = 2
	activeChan := make(chan bool, 10)
	releaseChan := make(chan bool)

	createBlockingProvider := func(name string) Provider {
		return &mockProvider{
			name: name,
			updateFunc: func(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
				activeChan <- true
				<-releaseChan
				return []string{}, 0, nil
			},
		}
	}

	for i := 0; i < 5; i++ {
		name := "provider" + string(rune('0'+i))
		Register(name, func(config Config) (Provider, error) {
			return createBlockingProvider(config.Name), nil
		})
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	executor := NewExecutor(ExecutorConfig{
		MaxParallel: maxParallel,
		Workspace:   t.TempDir(),
	}, logger)

	ctx := context.Background()
	done := make(chan bool)

	go func() {
		executor.Run(ctx, []string{"provider0", "provider1", "provider2", "provider3", "provider4"})
		done <- true
	}()

	// Wait for providers to start
	time.Sleep(100 * time.Millisecond)

	// Check that at most maxParallel providers are running
	activeCount := len(activeChan)
	if activeCount > maxParallel {
		t.Errorf("expected at most %d active providers, got %d", maxParallel, activeCount)
	}

	// Release all providers
	close(releaseChan)

	// Wait for execution to complete
	<-done
}

// TestExecutor_ProviderReturnsData tests that provider results are properly captured.
func TestExecutor_ProviderReturnsData(t *testing.T) {
	Reset()

	expectedURLs := []string{"https://example.com/vuln1", "https://example.com/vuln2"}
	expectedCount := 42

	provider1 := &mockProvider{
		name: "provider1",
		updateFunc: func(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
			return expectedURLs, expectedCount, nil
		},
	}

	Register("provider1", func(config Config) (Provider, error) {
		return provider1, nil
	})

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	executor := NewExecutor(ExecutorConfig{
		MaxParallel: 1,
		Workspace:   t.TempDir(),
	}, logger)

	ctx := context.Background()
	results, err := executor.Run(ctx, []string{"provider1"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	result := results[0]

	if len(result.URLs) != len(expectedURLs) {
		t.Errorf("expected %d URLs, got %d", len(expectedURLs), len(result.URLs))
	}

	for i, url := range expectedURLs {
		if result.URLs[i] != url {
			t.Errorf("expected URL[%d] = %q, got %q", i, url, result.URLs[i])
		}
	}

	if result.Count != expectedCount {
		t.Errorf("expected count %d, got %d", expectedCount, result.Count)
	}
}
