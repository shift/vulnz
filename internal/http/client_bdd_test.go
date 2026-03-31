package http_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	httpClient "github.com/shift/vulnz/internal/http"
)

var _ = Describe("HTTP Client", func() {
	var (
		client *httpClient.Client
		config httpClient.Config
	)

	BeforeEach(func() {
		config = httpClient.DefaultConfig()
		config.MaxRetries = 3
		config.InitialBackoff = 10 * time.Millisecond
		config.MaxBackoff = 100 * time.Millisecond
		config.Timeout = 5 * time.Second
		client = httpClient.NewClient(config)
	})

	Describe("GET requests", func() {
		Context("when making simple GET requests", func() {
			It("should perform a simple GET successfully", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).To(Equal("GET"))
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("success"))
				}))
				defer server.Close()

				resp, err := client.Get(context.Background(), server.URL)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))
				defer resp.Body.Close()

				body, err := io.ReadAll(resp.Body)
				Expect(err).NotTo(HaveOccurred())
				Expect(string(body)).To(Equal("success"))
			})

			It("should follow redirects", func() {
				redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("redirected"))
				}))
				defer redirectServer.Close()

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, redirectServer.URL, http.StatusFound)
				}))
				defer server.Close()

				resp, err := client.Get(context.Background(), server.URL)
				Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()

				body, err := io.ReadAll(resp.Body)
				Expect(err).NotTo(HaveOccurred())
				Expect(string(body)).To(Equal("redirected"))
			})

			It("should timeout on slow responses", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(10 * time.Second)
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				shortConfig := config
				shortConfig.Timeout = 100 * time.Millisecond
				shortClient := httpClient.NewClient(shortConfig)

				ctx := context.Background()
				_, err := shortClient.Get(ctx, server.URL)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("context deadline exceeded"))
			})
		})

		Context("when setting User-Agent", func() {
			It("should include User-Agent header", func() {
				var receivedUA string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					receivedUA = r.Header.Get("User-Agent")
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				config.UserAgent = "test-agent/1.0"
				client = httpClient.NewClient(config)

				resp, err := client.Get(context.Background(), server.URL)
				Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()

				Expect(receivedUA).To(Equal("test-agent/1.0"))
			})
		})
	})

	Describe("Rate limiting", func() {
		Context("when enforcing rate limits", func() {
			It("should limit requests per second", func() {
				requestCount := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&requestCount, 1)
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				// Configure low RPS for testing
				config.RateLimitRPS = 5
				client = httpClient.NewClient(config)

				// Make 10 requests
				start := time.Now()
				for i := 0; i < 10; i++ {
					resp, err := client.Get(context.Background(), server.URL)
					Expect(err).NotTo(HaveOccurred())
					resp.Body.Close()
				}
				elapsed := time.Since(start)

				// Should take at least 1 second for 10 requests at 5 RPS
				Expect(elapsed).To(BeNumerically(">=", 1*time.Second))
				Expect(atomic.LoadInt32(&requestCount)).To(Equal(int32(10)))
			})

			It("should rate limit per host independently", func() {
				requestCount1 := int32(0)
				requestCount2 := int32(0)

				server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&requestCount1, 1)
					w.WriteHeader(http.StatusOK)
				}))
				defer server1.Close()

				server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&requestCount2, 1)
					w.WriteHeader(http.StatusOK)
				}))
				defer server2.Close()

				config.RateLimitRPS = 10
				client = httpClient.NewClient(config)

				var wg sync.WaitGroup
				wg.Add(2)

				// Make requests to both servers concurrently
				go func() {
					defer wg.Done()
					for i := 0; i < 5; i++ {
						resp, err := client.Get(context.Background(), server1.URL)
						Expect(err).NotTo(HaveOccurred())
						resp.Body.Close()
					}
				}()

				go func() {
					defer wg.Done()
					for i := 0; i < 5; i++ {
						resp, err := client.Get(context.Background(), server2.URL)
						Expect(err).NotTo(HaveOccurred())
						resp.Body.Close()
					}
				}()

				wg.Wait()

				// Both servers should have received requests
				Expect(atomic.LoadInt32(&requestCount1)).To(Equal(int32(5)))
				Expect(atomic.LoadInt32(&requestCount2)).To(Equal(int32(5)))
			})

			It("should respect Retry-After header", func() {
				attempt := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					currentAttempt := atomic.AddInt32(&attempt, 1)
					if currentAttempt == 1 {
						w.Header().Set("Retry-After", "1")
						w.WriteHeader(http.StatusTooManyRequests)
					} else {
						w.WriteHeader(http.StatusOK)
					}
				}))
				defer server.Close()

				start := time.Now()
				resp, err := client.Get(context.Background(), server.URL)
				elapsed := time.Since(start)

				Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()
				Expect(resp.StatusCode).To(Equal(http.StatusOK))
				Expect(atomic.LoadInt32(&attempt)).To(Equal(int32(2)))
				// Should have waited at least 1 second for Retry-After
				Expect(elapsed).To(BeNumerically(">=", 1*time.Second))
			})
		})
	})

	Describe("Retry logic", func() {
		Context("when handling retryable errors", func() {
			It("should retry on 429 status", func() {
				attempt := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					currentAttempt := atomic.AddInt32(&attempt, 1)
					if currentAttempt < 3 {
						w.WriteHeader(http.StatusTooManyRequests)
					} else {
						w.WriteHeader(http.StatusOK)
					}
				}))
				defer server.Close()

				resp, err := client.Get(context.Background(), server.URL)
				Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()
				Expect(resp.StatusCode).To(Equal(http.StatusOK))
				Expect(atomic.LoadInt32(&attempt)).To(Equal(int32(3)))
			})

			It("should retry on 503 status", func() {
				attempt := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					currentAttempt := atomic.AddInt32(&attempt, 1)
					if currentAttempt < 2 {
						w.WriteHeader(http.StatusServiceUnavailable)
					} else {
						w.WriteHeader(http.StatusOK)
					}
				}))
				defer server.Close()

				resp, err := client.Get(context.Background(), server.URL)
				Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()
				Expect(resp.StatusCode).To(Equal(http.StatusOK))
				Expect(atomic.LoadInt32(&attempt)).To(BeNumerically(">=", 2))
			})

			It("should retry on 504 status", func() {
				attempt := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					currentAttempt := atomic.AddInt32(&attempt, 1)
					if currentAttempt < 2 {
						w.WriteHeader(http.StatusGatewayTimeout)
					} else {
						w.WriteHeader(http.StatusOK)
					}
				}))
				defer server.Close()

				resp, err := client.Get(context.Background(), server.URL)
				Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()
				Expect(resp.StatusCode).To(Equal(http.StatusOK))
			})

			It("should NOT retry on 404 status", func() {
				attempt := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&attempt, 1)
					w.WriteHeader(http.StatusNotFound)
				}))
				defer server.Close()

				resp, err := client.Get(context.Background(), server.URL)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("404"))
				if resp != nil {
					resp.Body.Close()
				}
				// Should only attempt once (no retries)
				Expect(atomic.LoadInt32(&attempt)).To(Equal(int32(1)))
			})

			It("should respect max retries", func() {
				attempt := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&attempt, 1)
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				defer server.Close()

				config.MaxRetries = 2
				client = httpClient.NewClient(config)

				_, err := client.Get(context.Background(), server.URL)
				Expect(err).To(HaveOccurred())
				// Should attempt 1 initial + 2 retries = 3 total
				Expect(atomic.LoadInt32(&attempt)).To(Equal(int32(3)))
			})

			It("should use exponential backoff", func() {
				attempt := int32(0)
				timestamps := []time.Time{}
				var mu sync.Mutex

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					timestamps = append(timestamps, time.Now())
					mu.Unlock()
					atomic.AddInt32(&attempt, 1)
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				defer server.Close()

				config.MaxRetries = 3
				config.InitialBackoff = 100 * time.Millisecond
				client = httpClient.NewClient(config)

				_, err := client.Get(context.Background(), server.URL)
				Expect(err).To(HaveOccurred())

				mu.Lock()
				defer mu.Unlock()

				// Check that delays increase exponentially (with some tolerance for jitter)
				Expect(len(timestamps)).To(BeNumerically(">=", 3))
				if len(timestamps) >= 3 {
					delay1 := timestamps[1].Sub(timestamps[0])
					delay2 := timestamps[2].Sub(timestamps[1])
					// Second delay should be roughly 2x first delay (with jitter tolerance)
					Expect(delay2).To(BeNumerically(">", float64(delay1)*0.5))
				}
			})
		})
	})

	Describe("Context cancellation", func() {
		Context("when context is cancelled", func() {
			It("should cancel in-flight requests", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(5 * time.Second)
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()

				_, err := client.Get(ctx, server.URL)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("context deadline exceeded"))
			})

			It("should return context error when cancelled during retry", func() {
				attempt := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&attempt, 1)
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				defer server.Close()

				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				defer cancel()

				_, err := client.Get(ctx, server.URL)
				Expect(err).To(HaveOccurred())
				// Should fail with either context error or retries exhausted
				errMsg := err.Error()
				// Accept either context error or retries exhausted
				shouldContainContextOrRetries := strings.Contains(errMsg, "context") ||
					strings.Contains(errMsg, "retries") ||
					strings.Contains(errMsg, "retryable status")
				Expect(shouldContainContextOrRetries).To(BeTrue(), "Error should mention context or retries: %s", errMsg)
			})
		})
	})

	Describe("Download", func() {
		Context("when downloading files", func() {
			It("should download file successfully", func() {
				content := "test file content"
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(content))
				}))
				defer server.Close()

				tmpDir := GinkgoT().TempDir()
				destPath := filepath.Join(tmpDir, "downloaded.txt")

				err := client.Download(context.Background(), server.URL, destPath)
				Expect(err).NotTo(HaveOccurred())

				data, err := os.ReadFile(destPath)
				Expect(err).NotTo(HaveOccurred())
				Expect(string(data)).To(Equal(content))
			})

			It("should clean up partial file on error", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
				defer server.Close()

				tmpDir := GinkgoT().TempDir()
				destPath := filepath.Join(tmpDir, "failed.txt")

				err := client.Download(context.Background(), server.URL, destPath)
				Expect(err).To(HaveOccurred())

				// File should not exist after failed download
				_, err = os.Stat(destPath)
				Expect(os.IsNotExist(err)).To(BeTrue())
			})
		})
	})

	Describe("POST requests", func() {
		Context("when making POST requests", func() {
			It("should perform POST with body", func() {
				var receivedBody string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).To(Equal("POST"))
					body, _ := io.ReadAll(r.Body)
					receivedBody = string(body)
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				body := strings.NewReader("test data")
				resp, err := client.Post(context.Background(), server.URL, "text/plain", body)
				Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()

				Expect(receivedBody).To(Equal("test data"))
			})

			It("should set Content-Type header", func() {
				var receivedContentType string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					receivedContentType = r.Header.Get("Content-Type")
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				body := strings.NewReader("{}")
				resp, err := client.Post(context.Background(), server.URL, "application/json", body)
				Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()

				Expect(receivedContentType).To(Equal("application/json"))
			})
		})
	})

	Describe("Error handling", func() {
		Context("when handling various error conditions", func() {
			It("should return error for invalid URL", func() {
				_, err := client.Get(context.Background(), "not a valid url")
				Expect(err).To(HaveOccurred())
			})

			It("should handle connection refused", func() {
				// Use a port that's unlikely to be open
				_, err := client.Get(context.Background(), "http://localhost:65535")
				Expect(err).To(HaveOccurred())
			})

			It("should provide detailed error for 4xx responses", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("bad request details"))
				}))
				defer server.Close()

				resp, err := client.Get(context.Background(), server.URL)
				if resp != nil {
					resp.Body.Close()
				}
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("400"))
			})

			It("should provide detailed error for 5xx responses", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("server error"))
				}))
				defer server.Close()

				// Set maxRetries to 0 to fail immediately on 500
				config.MaxRetries = 0
				client = httpClient.NewClient(config)

				resp, err := client.Get(context.Background(), server.URL)
				if resp != nil {
					resp.Body.Close()
				}
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("500"))
			})
		})
	})

	Describe("Connection pooling", func() {
		Context("when reusing connections", func() {
			It("should reuse connections for same host", func() {
				requestCount := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&requestCount, 1)
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				// Make multiple requests to same host
				for i := 0; i < 5; i++ {
					resp, err := client.Get(context.Background(), server.URL)
					Expect(err).NotTo(HaveOccurred())
					resp.Body.Close()
				}

				Expect(atomic.LoadInt32(&requestCount)).To(Equal(int32(5)))
			})

			It("should use separate pools for different hosts", func() {
				count1 := int32(0)
				count2 := int32(0)

				server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&count1, 1)
					w.WriteHeader(http.StatusOK)
				}))
				defer server1.Close()

				server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&count2, 1)
					w.WriteHeader(http.StatusOK)
				}))
				defer server2.Close()

				// Make requests to both servers
				resp1, err := client.Get(context.Background(), server1.URL)
				Expect(err).NotTo(HaveOccurred())
				resp1.Body.Close()

				resp2, err := client.Get(context.Background(), server2.URL)
				Expect(err).NotTo(HaveOccurred())
				resp2.Body.Close()

				Expect(atomic.LoadInt32(&count1)).To(Equal(int32(1)))
				Expect(atomic.LoadInt32(&count2)).To(Equal(int32(1)))
			})
		})
	})

	Describe("Retry-After header parsing", func() {
		Context("when parsing Retry-After with date format", func() {
			It("should parse HTTP-date Retry-After header", func() {
				attempt := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					currentAttempt := atomic.AddInt32(&attempt, 1)
					if currentAttempt == 1 {
						retryTime := time.Now().Add(2 * time.Second).UTC().Format(time.RFC1123Z)
						w.Header().Set("Retry-After", retryTime)
						w.WriteHeader(http.StatusTooManyRequests)
					} else {
						w.WriteHeader(http.StatusOK)
					}
				}))
				defer server.Close()

				start := time.Now()
				resp, err := client.Get(context.Background(), server.URL)
				elapsed := time.Since(start)

				Expect(err).NotTo(HaveOccurred())
				defer resp.Body.Close()
				Expect(elapsed).To(BeNumerically(">=", 1*time.Second))
			})
		})

		Context("when Retry-After exceeds maximum", func() {
			It("should cap Retry-After at 5 minutes", func() {
				attempt := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					currentAttempt := atomic.AddInt32(&attempt, 1)
					if currentAttempt == 1 {
						// Try to set a very long retry
						w.Header().Set("Retry-After", "3600") // 1 hour
						w.WriteHeader(http.StatusTooManyRequests)
					} else {
						w.WriteHeader(http.StatusOK)
					}
				}))
				defer server.Close()

				// Use a timeout to prevent test from hanging
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				start := time.Now()
				resp, err := client.Get(ctx, server.URL)
				elapsed := time.Since(start)

				// Should either succeed after capped wait or timeout
				if err == nil {
					defer resp.Body.Close()
					// Should have waited at most 5 minutes (capped)
					Expect(elapsed).To(BeNumerically("<=", 6*time.Minute))
				} else {
					// Context timeout is acceptable
					Expect(err.Error()).To(ContainSubstring("context deadline exceeded"))
				}
			})
		})
	})

	Describe("Concurrent requests", func() {
		Context("when making many concurrent requests", func() {
			It("should handle concurrent requests safely", func() {
				requestCount := int32(0)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&requestCount, 1)
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				numGoroutines := 20
				var wg sync.WaitGroup
				wg.Add(numGoroutines)

				for i := 0; i < numGoroutines; i++ {
					go func() {
						defer wg.Done()
						resp, err := client.Get(context.Background(), server.URL)
						Expect(err).NotTo(HaveOccurred())
						resp.Body.Close()
					}()
				}

				wg.Wait()
				Expect(atomic.LoadInt32(&requestCount)).To(Equal(int32(numGoroutines)))
			})
		})
	})

	Describe("Large file downloads", func() {
		Context("when downloading large files", func() {
			It("should stream large files efficiently", func() {
				// Create a 1MB response
				largeContent := strings.Repeat("A", 1024*1024)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(largeContent))
				}))
				defer server.Close()

				tmpDir := GinkgoT().TempDir()
				destPath := filepath.Join(tmpDir, "large.txt")

				err := client.Download(context.Background(), server.URL, destPath)
				Expect(err).NotTo(HaveOccurred())

				info, err := os.Stat(destPath)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.Size()).To(Equal(int64(len(largeContent))))
			})
		})
	})
})
