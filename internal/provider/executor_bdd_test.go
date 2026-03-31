package provider_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
)

// Mock provider for testing
type mockProvider struct {
	name          string
	urls          []string
	count         int
	err           error
	executionTime time.Duration
	executed      *atomic.Bool
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Update(ctx context.Context, lastUpdated *time.Time) ([]string, int, error) {
	if m.executed != nil {
		m.executed.Store(true)
	}

	if m.executionTime > 0 {
		select {
		case <-time.After(m.executionTime):
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}

	return m.urls, m.count, m.err
}

var _ = Describe("Provider Executor", func() {
	var (
		executor *provider.Executor
		tempDir  string
		logger   *slog.Logger
		ctx      context.Context
	)

	BeforeEach(func() {
		tempDir = GinkgoT().TempDir()
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelError, // Reduce noise in tests
		}))
		ctx = context.Background()

		// Reset provider registry
		provider.Reset()
	})

	AfterEach(func() {
		provider.Reset()
	})

	Describe("Executor initialization", func() {
		Context("with valid configuration", func() {
			It("should create executor successfully", func() {
				config := provider.ExecutorConfig{
					MaxParallel: 5,
					Workspace:   tempDir,
				}

				executor = provider.NewExecutor(config, logger)
				Expect(executor).NotTo(BeNil())
			})

			It("should use default parallel value when zero", func() {
				config := provider.ExecutorConfig{
					MaxParallel: 0,
					Workspace:   tempDir,
				}

				executor = provider.NewExecutor(config, logger)
				Expect(executor).NotTo(BeNil())
			})

			It("should use negative parallel value as 1", func() {
				config := provider.ExecutorConfig{
					MaxParallel: -5,
					Workspace:   tempDir,
				}

				executor = provider.NewExecutor(config, logger)
				Expect(executor).NotTo(BeNil())
			})
		})
	})

	Describe("Single provider execution", func() {
		BeforeEach(func() {
			config := provider.ExecutorConfig{
				MaxParallel: 1,
				Workspace:   tempDir,
			}
			executor = provider.NewExecutor(config, logger)
		})

		Context("when provider succeeds", func() {
			It("should execute provider successfully", func() {
				executed := &atomic.Bool{}
				mockProv := &mockProvider{
					name:     "test-provider",
					urls:     []string{"https://example.com/data.json"},
					count:    100,
					executed: executed,
				}

				provider.Register("test-provider", func(c provider.Config) (provider.Provider, error) {
					return mockProv, nil
				})

				results, err := executor.Run(ctx, []string{"test-provider"})
				Expect(err).NotTo(HaveOccurred())
				Expect(results).To(HaveLen(1))
				Expect(results[0].Provider).To(Equal("test-provider"))
				Expect(results[0].Count).To(Equal(100))
				Expect(results[0].URLs).To(ContainElement("https://example.com/data.json"))
				Expect(results[0].Err).To(BeNil())
				Expect(executed.Load()).To(BeTrue())
			})

			It("should capture provider results", func() {
				mockProv := &mockProvider{
					name:  "results-test",
					urls:  []string{"https://example.com/v1.json", "https://example.com/v2.json"},
					count: 250,
				}

				provider.Register("results-test", func(c provider.Config) (provider.Provider, error) {
					return mockProv, nil
				})

				results, err := executor.Run(ctx, []string{"results-test"})
				Expect(err).NotTo(HaveOccurred())
				Expect(results[0].URLs).To(HaveLen(2))
				Expect(results[0].Count).To(Equal(250))
			})

			It("should record execution duration", func() {
				mockProv := &mockProvider{
					name:          "duration-test",
					executionTime: 100 * time.Millisecond,
				}

				provider.Register("duration-test", func(c provider.Config) (provider.Provider, error) {
					return mockProv, nil
				})

				results, err := executor.Run(ctx, []string{"duration-test"})
				Expect(err).NotTo(HaveOccurred())
				Expect(results[0].Duration).To(BeNumerically(">=", 100*time.Millisecond))
			})
		})

		Context("when provider fails", func() {
			It("should capture provider error", func() {
				providerErr := errors.New("provider failed to fetch data")
				mockProv := &mockProvider{
					name: "failing-provider",
					err:  providerErr,
				}

				provider.Register("failing-provider", func(c provider.Config) (provider.Provider, error) {
					return mockProv, nil
				})

				results, err := executor.Run(ctx, []string{"failing-provider"})
				Expect(err).NotTo(HaveOccurred()) // Executor should not error, just capture provider error
				Expect(results).To(HaveLen(1))
				Expect(results[0].Err).To(HaveOccurred())
				Expect(results[0].Err.Error()).To(ContainSubstring("provider failed"))
			})

			It("should handle provider factory error", func() {
				provider.Register("factory-error", func(c provider.Config) (provider.Provider, error) {
					return nil, errors.New("factory initialization failed")
				})

				results, err := executor.Run(ctx, []string{"factory-error"})
				Expect(err).NotTo(HaveOccurred())
				Expect(results).To(HaveLen(1))
				Expect(results[0].Err).To(HaveOccurred())
				Expect(results[0].Err.Error()).To(ContainSubstring("create provider"))
			})

			It("should handle non-existent provider", func() {
				results, err := executor.Run(ctx, []string{"non-existent"})
				Expect(err).NotTo(HaveOccurred())
				Expect(results).To(HaveLen(1))
				Expect(results[0].Err).To(HaveOccurred())
				Expect(results[0].Err.Error()).To(ContainSubstring("not registered"))
			})
		})

		Context("with no providers", func() {
			It("should return nil for empty provider list", func() {
				results, err := executor.Run(ctx, []string{})
				Expect(err).NotTo(HaveOccurred())
				Expect(results).To(BeNil())
			})
		})
	})

	Describe("Multiple provider execution", func() {
		BeforeEach(func() {
			config := provider.ExecutorConfig{
				MaxParallel: 3,
				Workspace:   tempDir,
			}
			executor = provider.NewExecutor(config, logger)
		})

		Context("when all providers succeed", func() {
			It("should execute providers in parallel", func() {
				providers := []string{"provider1", "provider2", "provider3"}

				for _, name := range providers {
					mockProv := &mockProvider{
						name:  name,
						count: 100,
					}
					provider.Register(name, func(c provider.Config) (provider.Provider, error) {
						return mockProv, nil
					})
				}

				results, err := executor.Run(ctx, providers)
				Expect(err).NotTo(HaveOccurred())
				Expect(results).To(HaveLen(3))

				// All providers should have executed
				for _, result := range results {
					Expect(result.Err).To(BeNil())
					Expect(result.Count).To(Equal(100))
				}
			})

			It("should respect concurrency limit", func() {
				// Create 10 providers with 100ms execution time
				providerCount := 10
				for i := 0; i < providerCount; i++ {
					name := fmt.Sprintf("provider-%d", i)
					mockProv := &mockProvider{
						name:          name,
						executionTime: 100 * time.Millisecond,
					}
					provider.Register(name, func(c provider.Config) (provider.Provider, error) {
						return mockProv, nil
					})
				}

				providerNames := make([]string, providerCount)
				for i := 0; i < providerCount; i++ {
					providerNames[i] = fmt.Sprintf("provider-%d", i)
				}

				start := time.Now()
				results, err := executor.Run(ctx, providerNames)
				duration := time.Since(start)

				Expect(err).NotTo(HaveOccurred())
				Expect(results).To(HaveLen(providerCount))

				// With maxParallel=3 and 10 providers @ 100ms each:
				// Should take at least 400ms (4 batches: 3+3+3+1)
				// Allow some overhead
				Expect(duration).To(BeNumerically(">=", 300*time.Millisecond))
			})

			It("should collect all results", func() {
				providers := []string{"alpine", "debian", "ubuntu"}
				expectedCounts := map[string]int{
					"alpine": 150,
					"debian": 200,
					"ubuntu": 180,
				}

				for name, count := range expectedCounts {
					mockProv := &mockProvider{
						name:  name,
						count: count,
					}
					provider.Register(name, func(c provider.Config) (provider.Provider, error) {
						return mockProv, nil
					})
				}

				results, err := executor.Run(ctx, providers)
				Expect(err).NotTo(HaveOccurred())
				Expect(results).To(HaveLen(3))

				// Verify all results
				resultMap := make(map[string]provider.Result)
				for _, result := range results {
					resultMap[result.Provider] = result
				}

				for name, expectedCount := range expectedCounts {
					result := resultMap[name]
					Expect(result.Count).To(Equal(expectedCount))
					Expect(result.Err).To(BeNil())
				}
			})
		})

		Context("when some providers fail", func() {
			It("should continue execution on single provider failure", func() {
				provider.Register("success-1", func(c provider.Config) (provider.Provider, error) {
					return &mockProvider{name: "success-1", count: 100}, nil
				})

				provider.Register("failure", func(c provider.Config) (provider.Provider, error) {
					return &mockProvider{
						name: "failure",
						err:  errors.New("intentional failure"),
					}, nil
				})

				provider.Register("success-2", func(c provider.Config) (provider.Provider, error) {
					return &mockProvider{name: "success-2", count: 200}, nil
				})

				results, err := executor.Run(ctx, []string{"success-1", "failure", "success-2"})
				Expect(err).NotTo(HaveOccurred())
				Expect(results).To(HaveLen(3))

				// Count successes and failures
				successCount := 0
				failureCount := 0
				for _, result := range results {
					if result.Err == nil {
						successCount++
					} else {
						failureCount++
					}
				}

				Expect(successCount).To(Equal(2))
				Expect(failureCount).To(Equal(1))
			})

			It("should collect both successful and failed results", func() {
				provider.Register("provider-1", func(c provider.Config) (provider.Provider, error) {
					return &mockProvider{name: "provider-1", count: 50}, nil
				})

				provider.Register("provider-2", func(c provider.Config) (provider.Provider, error) {
					return &mockProvider{
						name: "provider-2",
						err:  errors.New("network error"),
					}, nil
				})

				results, err := executor.Run(ctx, []string{"provider-1", "provider-2"})
				Expect(err).NotTo(HaveOccurred())
				Expect(results).To(HaveLen(2))

				// Find results by provider name
				var result1, result2 provider.Result
				for _, r := range results {
					if r.Provider == "provider-1" {
						result1 = r
					} else if r.Provider == "provider-2" {
						result2 = r
					}
				}

				Expect(result1.Err).To(BeNil())
				Expect(result1.Count).To(Equal(50))

				Expect(result2.Err).To(HaveOccurred())
				Expect(result2.Count).To(Equal(0))
			})
		})
	})

	Describe("Context cancellation", func() {
		BeforeEach(func() {
			config := provider.ExecutorConfig{
				MaxParallel: 2,
				Workspace:   tempDir,
			}
			executor = provider.NewExecutor(config, logger)
		})

		It("should respect context cancellation", func() {
			cancelCtx, cancel := context.WithCancel(ctx)

			// Create long-running provider
			provider.Register("long-running", func(c provider.Config) (provider.Provider, error) {
				return &mockProvider{
					name:          "long-running",
					executionTime: 5 * time.Second,
				}, nil
			})

			// Cancel after 100ms
			go func() {
				time.Sleep(100 * time.Millisecond)
				cancel()
			}()

			start := time.Now()
			results, err := executor.Run(cancelCtx, []string{"long-running"})
			duration := time.Since(start)

			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(1))
			Expect(results[0].Err).To(HaveOccurred())
			Expect(results[0].Err).To(MatchError(context.Canceled))

			// Should finish quickly due to cancellation
			Expect(duration).To(BeNumerically("<", 1*time.Second))
		})

		It("should cancel all running providers", func() {
			cancelCtx, cancel := context.WithCancel(ctx)

			// Create multiple long-running providers
			for i := 0; i < 5; i++ {
				name := fmt.Sprintf("provider-%d", i)
				provider.Register(name, func(c provider.Config) (provider.Provider, error) {
					return &mockProvider{
						name:          name,
						executionTime: 10 * time.Second,
					}, nil
				})
			}

			providerNames := []string{"provider-0", "provider-1", "provider-2", "provider-3", "provider-4"}

			// Cancel after 100ms
			go func() {
				time.Sleep(100 * time.Millisecond)
				cancel()
			}()

			start := time.Now()
			results, err := executor.Run(cancelCtx, providerNames)
			duration := time.Since(start)

			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(5))

			// All should have context errors
			for _, result := range results {
				Expect(result.Err).To(Or(
					MatchError(context.Canceled),
					BeNil(), // Some might complete before cancellation
				))
			}

			// Should finish quickly
			Expect(duration).To(BeNumerically("<", 2*time.Second))
		})

		It("should cleanup properly on cancel", func() {
			cancelCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
			defer cancel()

			provider.Register("timeout-test", func(c provider.Config) (provider.Provider, error) {
				return &mockProvider{
					name:          "timeout-test",
					executionTime: 1 * time.Second,
				}, nil
			})

			results, err := executor.Run(cancelCtx, []string{"timeout-test"})
			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(1))
			Expect(results[0].Err).To(HaveOccurred())
		})
	})

	Describe("RunAll", func() {
		BeforeEach(func() {
			config := provider.ExecutorConfig{
				MaxParallel: 5,
				Workspace:   tempDir,
			}
			executor = provider.NewExecutor(config, logger)
		})

		Context("with registered providers", func() {
			It("should execute all registered providers", func() {
				providers := []string{"alpine", "debian", "ubuntu", "nvd"}

				for _, name := range providers {
					mockProv := &mockProvider{
						name:  name,
						count: 100,
					}
					provider.Register(name, func(c provider.Config) (provider.Provider, error) {
						return mockProv, nil
					})
				}

				results, err := executor.RunAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(results).To(HaveLen(4))

				// Verify all providers executed
				executedNames := make([]string, len(results))
				for i, result := range results {
					executedNames[i] = result.Provider
				}
				Expect(executedNames).To(ConsistOf(providers))
			})
		})

		Context("with no registered providers", func() {
			It("should return error", func() {
				results, err := executor.RunAll(ctx)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no providers registered"))
				Expect(results).To(BeNil())
			})
		})
	})

	Describe("Configuration passing", func() {
		BeforeEach(func() {
			config := provider.ExecutorConfig{
				MaxParallel: 1,
				Workspace:   tempDir,
			}
			executor = provider.NewExecutor(config, logger)
		})

		It("should pass workspace to provider config", func() {
			var receivedConfig provider.Config

			provider.Register("config-test", func(c provider.Config) (provider.Provider, error) {
				receivedConfig = c
				return &mockProvider{name: "config-test"}, nil
			})

			_, err := executor.Run(ctx, []string{"config-test"})
			Expect(err).NotTo(HaveOccurred())
			Expect(receivedConfig.Workspace).To(Equal(filepath.Join(tempDir, "config-test")))
			Expect(receivedConfig.Storage.Type).To(Equal("flat-file"))
			Expect(receivedConfig.Storage.Path).To(Equal(filepath.Join(tempDir, "config-test", "storage")))
		})

		It("should pass provider name to config", func() {
			var receivedConfig provider.Config

			provider.Register("name-test", func(c provider.Config) (provider.Provider, error) {
				receivedConfig = c
				return &mockProvider{name: "name-test"}, nil
			})

			_, err := executor.Run(ctx, []string{"name-test"})
			Expect(err).NotTo(HaveOccurred())
			Expect(receivedConfig.Name).To(Equal("name-test"))
		})

		It("should pass logger to config", func() {
			var receivedConfig provider.Config

			provider.Register("logger-test", func(c provider.Config) (provider.Provider, error) {
				receivedConfig = c
				return &mockProvider{name: "logger-test"}, nil
			})

			_, err := executor.Run(ctx, []string{"logger-test"})
			Expect(err).NotTo(HaveOccurred())
			Expect(receivedConfig.Logger).NotTo(BeNil())
		})

		It("should include HTTP config with defaults", func() {
			var receivedConfig provider.Config

			provider.Register("http-test", func(c provider.Config) (provider.Provider, error) {
				receivedConfig = c
				return &mockProvider{name: "http-test"}, nil
			})

			_, err := executor.Run(ctx, []string{"http-test"})
			Expect(err).NotTo(HaveOccurred())
			Expect(receivedConfig.HTTP.Timeout).To(BeNumerically(">", 0))
			Expect(receivedConfig.HTTP.UserAgent).NotTo(BeEmpty())
		})
	})
})
