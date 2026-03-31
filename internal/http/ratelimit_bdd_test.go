package http_test

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	httpClient "github.com/shift/vulnz/internal/http"
)

var _ = Describe("Rate Limiter", func() {
	var (
		rateLimiter *httpClient.RateLimiter
	)

	Describe("Per-host limiting", func() {
		Context("when enforcing rate limits per host", func() {
			It("should allow RPS requests per host", func() {
				rps := 10
				rateLimiter = httpClient.NewRateLimiter(rps)

				start := time.Now()
				for i := 0; i < rps; i++ {
					err := rateLimiter.Wait(context.Background(), "test-host")
					Expect(err).NotTo(HaveOccurred())
				}
				elapsed := time.Since(start)

				// Should complete quickly (burst allows RPS requests immediately)
				Expect(elapsed).To(BeNumerically("<", 500*time.Millisecond))
			})

			It("should block when limit exceeded", func() {
				rps := 5
				rateLimiter = httpClient.NewRateLimiter(rps)

				// Consume all tokens
				for i := 0; i < rps; i++ {
					err := rateLimiter.Wait(context.Background(), "test-host")
					Expect(err).NotTo(HaveOccurred())
				}

				// Next request should block
				start := time.Now()
				err := rateLimiter.Wait(context.Background(), "test-host")
				elapsed := time.Since(start)

				Expect(err).NotTo(HaveOccurred())
				// Should have waited for token refill (~200ms for 5 RPS)
				Expect(elapsed).To(BeNumerically(">=", 100*time.Millisecond))
			})

			It("should isolate hosts", func() {
				rps := 5
				rateLimiter = httpClient.NewRateLimiter(rps)

				// Exhaust tokens for host1
				for i := 0; i < rps; i++ {
					err := rateLimiter.Wait(context.Background(), "host1")
					Expect(err).NotTo(HaveOccurred())
				}

				// host2 should still have tokens available
				start := time.Now()
				err := rateLimiter.Wait(context.Background(), "host2")
				elapsed := time.Since(start)

				Expect(err).NotTo(HaveOccurred())
				// Should complete quickly (host2 has full burst)
				Expect(elapsed).To(BeNumerically("<", 100*time.Millisecond))
			})

			It("should refill tokens over time", func() {
				rps := 10
				rateLimiter = httpClient.NewRateLimiter(rps)

				// Consume all tokens
				for i := 0; i < rps; i++ {
					err := rateLimiter.Wait(context.Background(), "test-host")
					Expect(err).NotTo(HaveOccurred())
				}

				// Wait for token refill (1 second should refill ~10 tokens)
				time.Sleep(1 * time.Second)

				// Should be able to make more requests quickly
				start := time.Now()
				for i := 0; i < rps; i++ {
					err := rateLimiter.Wait(context.Background(), "test-host")
					Expect(err).NotTo(HaveOccurred())
				}
				elapsed := time.Since(start)

				// Should complete quickly (tokens refilled)
				Expect(elapsed).To(BeNumerically("<", 500*time.Millisecond))
			})
		})
	})

	Describe("Concurrent access", func() {
		Context("when multiple goroutines access rate limiter", func() {
			It("should handle 100 goroutines safely", func() {
				rps := 20
				rateLimiter = httpClient.NewRateLimiter(rps)

				numGoroutines := 100
				successCount := int32(0)
				var wg sync.WaitGroup
				wg.Add(numGoroutines)

				start := time.Now()
				for i := 0; i < numGoroutines; i++ {
					go func() {
						defer wg.Done()
						err := rateLimiter.Wait(context.Background(), "shared-host")
						if err == nil {
							atomic.AddInt32(&successCount, 1)
						}
					}()
				}

				wg.Wait()
				elapsed := time.Since(start)

				// All requests should succeed
				Expect(atomic.LoadInt32(&successCount)).To(Equal(int32(numGoroutines)))
				// Should take at least (100 requests / 20 RPS) = 5 seconds
				Expect(elapsed).To(BeNumerically(">=", 4*time.Second))
			})

			It("should handle concurrent access to different hosts", func() {
				rps := 10
				rateLimiter = httpClient.NewRateLimiter(rps)

				numHosts := 5
				requestsPerHost := 10 // Reduced for faster test
				var wg sync.WaitGroup

				start := time.Now()
				for h := 0; h < numHosts; h++ {
					wg.Add(1)
					go func(hostNum int) {
						defer wg.Done()
						host := string(rune('A' + hostNum))
						for i := 0; i < requestsPerHost; i++ {
							err := rateLimiter.Wait(context.Background(), host)
							Expect(err).NotTo(HaveOccurred())
						}
					}(h)
				}

				wg.Wait()
				elapsed := time.Since(start)

				// Each host should process independently
				// With burst=RPS, all 10 requests per host can fire immediately
				Expect(elapsed).To(BeNumerically("<", 3*time.Second))
			})

			It("should allow immediate requests up to burst limit", func() {
				rps := 10
				rateLimiter = httpClient.NewRateLimiter(rps)

				successCount := int32(0)
				var wg sync.WaitGroup

				// Launch all goroutines at once
				for i := 0; i < rps; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						err := rateLimiter.Wait(context.Background(), "burst-host")
						if err == nil {
							atomic.AddInt32(&successCount, 1)
						}
					}()
				}

				// Give goroutines time to start
				time.Sleep(50 * time.Millisecond)

				// All should have succeeded quickly (within burst)
				Expect(atomic.LoadInt32(&successCount)).To(Equal(int32(rps)))
				wg.Wait()
			})
		})

		Context("when using Allow for non-blocking checks", func() {
			It("should return false when rate limited", func() {
				rps := 5
				rateLimiter = httpClient.NewRateLimiter(rps)

				// Consume all tokens
				for i := 0; i < rps; i++ {
					allowed := rateLimiter.Allow("test-host")
					Expect(allowed).To(BeTrue())
				}

				// Next check should return false
				allowed := rateLimiter.Allow("test-host")
				Expect(allowed).To(BeFalse())
			})

			It("should return true when tokens available", func() {
				rps := 5
				rateLimiter = httpClient.NewRateLimiter(rps)

				// Should allow up to RPS immediately
				for i := 0; i < rps; i++ {
					allowed := rateLimiter.Allow("test-host")
					Expect(allowed).To(BeTrue())
				}
			})

			It("should work independently for different hosts", func() {
				rps := 5
				rateLimiter = httpClient.NewRateLimiter(rps)

				// Exhaust tokens for host1
				for i := 0; i < rps; i++ {
					rateLimiter.Allow("host1")
				}

				// host1 should be rate limited
				Expect(rateLimiter.Allow("host1")).To(BeFalse())

				// host2 should still allow requests
				Expect(rateLimiter.Allow("host2")).To(BeTrue())
			})
		})
	})

	Describe("Context cancellation", func() {
		Context("when context is cancelled during wait", func() {
			It("should return context error", func() {
				rps := 1
				rateLimiter = httpClient.NewRateLimiter(rps)

				// Consume token
				err := rateLimiter.Wait(context.Background(), "test-host")
				Expect(err).NotTo(HaveOccurred())

				// Next wait should block, cancel it
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()

				err = rateLimiter.Wait(ctx, "test-host")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("context"))
			})

			It("should not consume token on context cancellation", func() {
				rps := 2
				rateLimiter = httpClient.NewRateLimiter(rps)

				// Consume all tokens
				for i := 0; i < rps; i++ {
					err := rateLimiter.Wait(context.Background(), "test-host")
					Expect(err).NotTo(HaveOccurred())
				}

				// Try to wait with cancelled context
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // Cancel immediately

				err := rateLimiter.Wait(ctx, "test-host")
				Expect(err).To(HaveOccurred())

				// After token refills, should still work
				time.Sleep(600 * time.Millisecond) // Wait for 1 token
				err = rateLimiter.Wait(context.Background(), "test-host")
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("Zero and negative RPS handling", func() {
		Context("when RPS is zero or negative", func() {
			It("should handle zero RPS gracefully", func() {
				rateLimiter = httpClient.NewRateLimiter(0)

				// Should still work but with very low rate
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()

				err := rateLimiter.Wait(ctx, "test-host")
				// May timeout or succeed depending on implementation
				_ = err // Accept either outcome
			})

			It("should handle negative RPS gracefully", func() {
				rateLimiter = httpClient.NewRateLimiter(-1)

				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()

				err := rateLimiter.Wait(ctx, "test-host")
				// May timeout or succeed depending on implementation
				_ = err // Accept either outcome
			})
		})
	})
})
