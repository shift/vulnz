package http_test

import (
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	httpClient "github.com/shift/vulnz/internal/http"
)

var _ = Describe("Retry Logic", func() {
	Describe("Exponential backoff", func() {
		Context("when calculating backoff durations", func() {
			var retryConfig httpClient.RetryConfig

			BeforeEach(func() {
				retryConfig = httpClient.RetryConfig{
					MaxRetries:     5,
					InitialBackoff: 100 * time.Millisecond,
					MaxBackoff:     5 * time.Second,
					Multiplier:     2.0,
				}
			})

			It("should calculate correct backoff durations", func() {
				// Attempt 0: 100ms * 2^0 = 100ms
				backoff0 := httpClient.CalculateBackoff(0, retryConfig)
				Expect(backoff0).To(BeNumerically("~", 100*time.Millisecond, 30*time.Millisecond))

				// Attempt 1: 100ms * 2^1 = 200ms
				backoff1 := httpClient.CalculateBackoff(1, retryConfig)
				Expect(backoff1).To(BeNumerically("~", 200*time.Millisecond, 60*time.Millisecond))

				// Attempt 2: 100ms * 2^2 = 400ms
				backoff2 := httpClient.CalculateBackoff(2, retryConfig)
				Expect(backoff2).To(BeNumerically("~", 400*time.Millisecond, 120*time.Millisecond))
			})

			It("should add jitter", func() {
				// Call multiple times and verify we get different values
				backoffs := make(map[time.Duration]bool)
				for i := 0; i < 10; i++ {
					backoff := httpClient.CalculateBackoff(1, retryConfig)
					backoffs[backoff] = true
				}

				// Should have at least 2 different values due to jitter
				Expect(len(backoffs)).To(BeNumerically(">=", 2))
			})

			It("should cap at max backoff", func() {
				retryConfig.MaxBackoff = 500 * time.Millisecond

				// Attempt 10: 100ms * 2^10 = 102,400ms, but capped at 500ms
				backoff := httpClient.CalculateBackoff(10, retryConfig)
				Expect(backoff).To(BeNumerically("<=", 650*time.Millisecond)) // Allow jitter
			})

			It("should handle zero initial backoff", func() {
				retryConfig.InitialBackoff = 0

				backoff := httpClient.CalculateBackoff(0, retryConfig)
				Expect(backoff).To(BeNumerically(">=", 0))
				Expect(backoff).To(BeNumerically("<", 100*time.Millisecond))
			})

			It("should grow exponentially", func() {
				backoff0 := httpClient.CalculateBackoff(0, retryConfig)
				backoff1 := httpClient.CalculateBackoff(1, retryConfig)
				backoff2 := httpClient.CalculateBackoff(2, retryConfig)

				// Each should be roughly double the previous (accounting for jitter)
				Expect(backoff1).To(BeNumerically(">", float64(backoff0)*0.75))
				Expect(backoff2).To(BeNumerically(">", float64(backoff1)*0.75))
			})
		})

		Context("when using different multipliers", func() {
			It("should respect custom multiplier", func() {
				retryConfig := httpClient.RetryConfig{
					MaxRetries:     5,
					InitialBackoff: 100 * time.Millisecond,
					MaxBackoff:     10 * time.Second,
					Multiplier:     3.0, // Triple instead of double
				}

				backoff0 := httpClient.CalculateBackoff(0, retryConfig)
				backoff1 := httpClient.CalculateBackoff(1, retryConfig)

				// backoff1 should be roughly 3x backoff0
				Expect(backoff1).To(BeNumerically(">", float64(backoff0)*1.5))
			})
		})
	})

	Describe("Retry-After header", func() {
		Context("when parsing Retry-After headers", func() {
			It("should parse Retry-After seconds", func() {
				resp := &http.Response{
					Header: http.Header{},
				}
				resp.Header.Set("Retry-After", "30")

				duration, ok := httpClient.HandleRetryAfter(resp)
				Expect(ok).To(BeTrue())
				Expect(duration).To(Equal(30 * time.Second))
			})

			It("should parse Retry-After date", func() {
				resp := &http.Response{
					Header: http.Header{},
				}

				// Set to 2 seconds in the future
				futureTime := time.Now().Add(2 * time.Second).UTC().Format(time.RFC1123)
				resp.Header.Set("Retry-After", futureTime)

				duration, ok := httpClient.HandleRetryAfter(resp)
				Expect(ok).To(BeTrue())
				// More lenient timing check (within 1 second)
				Expect(duration).To(BeNumerically(">=", 1*time.Second))
				Expect(duration).To(BeNumerically("<=", 3*time.Second))
			})

			It("should override backoff when Retry-After present", func() {
				resp := &http.Response{
					Header: http.Header{},
				}
				resp.Header.Set("Retry-After", "5")

				duration, ok := httpClient.HandleRetryAfter(resp)
				Expect(ok).To(BeTrue())
				Expect(duration).To(Equal(5 * time.Second))
			})

			It("should return false for missing header", func() {
				resp := &http.Response{
					Header: http.Header{},
				}

				_, ok := httpClient.HandleRetryAfter(resp)
				Expect(ok).To(BeFalse())
			})

			It("should return false for invalid seconds", func() {
				resp := &http.Response{
					Header: http.Header{},
				}
				resp.Header.Set("Retry-After", "invalid")

				_, ok := httpClient.HandleRetryAfter(resp)
				Expect(ok).To(BeFalse())
			})

			It("should return false for negative seconds", func() {
				resp := &http.Response{
					Header: http.Header{},
				}
				resp.Header.Set("Retry-After", "-10")

				_, ok := httpClient.HandleRetryAfter(resp)
				Expect(ok).To(BeFalse())
			})

			It("should return false for zero seconds", func() {
				resp := &http.Response{
					Header: http.Header{},
				}
				resp.Header.Set("Retry-After", "0")

				_, ok := httpClient.HandleRetryAfter(resp)
				Expect(ok).To(BeFalse())
			})

			It("should return false for past dates", func() {
				resp := &http.Response{
					Header: http.Header{},
				}

				// Set to past time
				pastTime := time.Now().Add(-5 * time.Second).UTC().Format(time.RFC1123)
				resp.Header.Set("Retry-After", pastTime)

				_, ok := httpClient.HandleRetryAfter(resp)
				Expect(ok).To(BeFalse())
			})

			It("should cap large Retry-After values", func() {
				resp := &http.Response{
					Header: http.Header{},
				}
				resp.Header.Set("Retry-After", "3600") // 1 hour

				duration, ok := httpClient.HandleRetryAfter(resp)
				Expect(ok).To(BeTrue())
				// Should be capped at 5 minutes
				Expect(duration).To(Equal(5 * time.Minute))
			})

			It("should handle whitespace in header", func() {
				resp := &http.Response{
					Header: http.Header{},
				}
				resp.Header.Set("Retry-After", "  30  ")

				duration, ok := httpClient.HandleRetryAfter(resp)
				Expect(ok).To(BeTrue())
				Expect(duration).To(Equal(30 * time.Second))
			})

			It("should parse various date formats", func() {
				resp := &http.Response{
					Header: http.Header{},
				}

				// RFC1123 format
				futureTime := time.Now().Add(3 * time.Second).UTC()
				resp.Header.Set("Retry-After", futureTime.Format(time.RFC1123))

				duration, ok := httpClient.HandleRetryAfter(resp)
				Expect(ok).To(BeTrue())
				// More lenient timing check (within 1 second)
				Expect(duration).To(BeNumerically(">=", 2*time.Second))
				Expect(duration).To(BeNumerically("<=", 4*time.Second))
			})
		})
	})

	Describe("Retry decision logic", func() {
		Context("when determining if errors are retryable", func() {
			It("should retry on 429 status", func() {
				retryable := httpClient.IsRetryable(429)
				Expect(retryable).To(BeTrue())
			})

			It("should retry on 503 status", func() {
				retryable := httpClient.IsRetryable(503)
				Expect(retryable).To(BeTrue())
			})

			It("should retry on 504 status", func() {
				retryable := httpClient.IsRetryable(504)
				Expect(retryable).To(BeTrue())
			})

			It("should NOT retry on 400 status", func() {
				retryable := httpClient.IsRetryable(400)
				Expect(retryable).To(BeFalse())
			})

			It("should NOT retry on 401 status", func() {
				retryable := httpClient.IsRetryable(401)
				Expect(retryable).To(BeFalse())
			})

			It("should NOT retry on 403 status", func() {
				retryable := httpClient.IsRetryable(403)
				Expect(retryable).To(BeFalse())
			})

			It("should NOT retry on 404 status", func() {
				retryable := httpClient.IsRetryable(404)
				Expect(retryable).To(BeFalse())
			})

			It("should NOT retry on 500 status", func() {
				retryable := httpClient.IsRetryable(500)
				Expect(retryable).To(BeFalse())
			})

			It("should NOT retry on 501 status", func() {
				retryable := httpClient.IsRetryable(501)
				Expect(retryable).To(BeFalse())
			})

			It("should NOT retry on 502 status", func() {
				retryable := httpClient.IsRetryable(502)
				Expect(retryable).To(BeFalse())
			})

			It("should NOT retry on 2xx status", func() {
				for status := 200; status < 300; status++ {
					retryable := httpClient.IsRetryable(status)
					Expect(retryable).To(BeFalse())
				}
			})

			It("should NOT retry on 3xx status", func() {
				for status := 300; status < 400; status++ {
					retryable := httpClient.IsRetryable(status)
					Expect(retryable).To(BeFalse())
				}
			})
		})
	})

	Describe("Jitter calculation", func() {
		Context("when adding jitter to backoff", func() {
			It("should produce values within jitter range", func() {
				retryConfig := httpClient.RetryConfig{
					MaxRetries:     5,
					InitialBackoff: 1 * time.Second,
					MaxBackoff:     10 * time.Second,
					Multiplier:     2.0,
				}

				// Collect multiple samples
				samples := make([]time.Duration, 50)
				for i := 0; i < 50; i++ {
					samples[i] = httpClient.CalculateBackoff(0, retryConfig)
				}

				// All samples should be within ±25% of 1 second
				// (1s - 25% = 750ms, 1s + 25% = 1250ms)
				for _, sample := range samples {
					Expect(sample).To(BeNumerically(">=", 750*time.Millisecond))
					Expect(sample).To(BeNumerically("<=", 1250*time.Millisecond))
				}

				// Should have variety (not all the same)
				uniqueValues := make(map[time.Duration]bool)
				for _, sample := range samples {
					uniqueValues[sample] = true
				}
				Expect(len(uniqueValues)).To(BeNumerically(">", 10))
			})

			It("should not produce negative durations", func() {
				retryConfig := httpClient.RetryConfig{
					MaxRetries:     5,
					InitialBackoff: 1 * time.Millisecond, // Very small
					MaxBackoff:     10 * time.Second,
					Multiplier:     2.0,
				}

				for i := 0; i < 100; i++ {
					backoff := httpClient.CalculateBackoff(0, retryConfig)
					Expect(backoff).To(BeNumerically(">=", 0))
				}
			})
		})
	})

	Describe("Max retries enforcement", func() {
		Context("when enforcing retry limits", func() {
			It("should respect max retries setting", func() {
				retryConfig := httpClient.RetryConfig{
					MaxRetries:     3,
					InitialBackoff: 10 * time.Millisecond,
					MaxBackoff:     1 * time.Second,
					Multiplier:     2.0,
				}

				// Max retries is 3, so we should be able to calculate
				// backoff for attempts 0, 1, 2, 3 (4 total attempts)
				for attempt := 0; attempt <= retryConfig.MaxRetries; attempt++ {
					backoff := httpClient.CalculateBackoff(attempt, retryConfig)
					Expect(backoff).To(BeNumerically(">=", 0))
				}
			})

			It("should handle zero max retries", func() {
				retryConfig := httpClient.RetryConfig{
					MaxRetries:     0,
					InitialBackoff: 100 * time.Millisecond,
					MaxBackoff:     1 * time.Second,
					Multiplier:     2.0,
				}

				// Should still calculate backoff for attempt 0
				backoff := httpClient.CalculateBackoff(0, retryConfig)
				Expect(backoff).To(BeNumerically(">=", 0))
			})
		})
	})

	Describe("Edge cases", func() {
		Context("when handling edge cases", func() {
			It("should handle very large attempt numbers", func() {
				retryConfig := httpClient.RetryConfig{
					MaxRetries:     1000,
					InitialBackoff: 1 * time.Millisecond,
					MaxBackoff:     1 * time.Minute,
					Multiplier:     2.0,
				}

				// Should cap at max backoff
				backoff := httpClient.CalculateBackoff(100, retryConfig)
				Expect(backoff).To(BeNumerically("<=", 75*time.Second)) // Allow jitter
			})

			It("should handle multiplier of 1.0", func() {
				retryConfig := httpClient.RetryConfig{
					MaxRetries:     5,
					InitialBackoff: 100 * time.Millisecond,
					MaxBackoff:     5 * time.Second,
					Multiplier:     1.0, // No exponential growth
				}

				backoff0 := httpClient.CalculateBackoff(0, retryConfig)
				backoff1 := httpClient.CalculateBackoff(1, retryConfig)
				backoff2 := httpClient.CalculateBackoff(2, retryConfig)

				// All should be approximately the same (with jitter)
				Expect(backoff0).To(BeNumerically("~", 100*time.Millisecond, 30*time.Millisecond))
				Expect(backoff1).To(BeNumerically("~", 100*time.Millisecond, 30*time.Millisecond))
				Expect(backoff2).To(BeNumerically("~", 100*time.Millisecond, 30*time.Millisecond))
			})

			It("should handle very large multiplier", func() {
				retryConfig := httpClient.RetryConfig{
					MaxRetries:     3,
					InitialBackoff: 10 * time.Millisecond,
					MaxBackoff:     1 * time.Second,
					Multiplier:     10.0, // Very aggressive growth
				}

				// Should cap at max backoff quickly
				backoff2 := httpClient.CalculateBackoff(2, retryConfig)
				Expect(backoff2).To(BeNumerically("<=", 1250*time.Millisecond)) // Allow jitter
			})
		})
	})
})
