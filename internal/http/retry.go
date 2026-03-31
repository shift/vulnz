package http

import (
	"math"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RetryConfig defines retry behavior configuration
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Multiplier     float64
}

// DefaultRetryConfig returns retry configuration with sensible defaults
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     5,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     60 * time.Second,
		Multiplier:     2.0,
	}
}

// shouldRetry determines if an error or status code should be retried
func shouldRetry(statusCode int, err error) bool {
	// Network errors are retryable
	if err != nil {
		// Timeout errors
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true
		}
		// Temporary network errors
		if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
			return true
		}
		// Connection refused, reset, etc.
		errStr := err.Error()
		if strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "connection reset") ||
			strings.Contains(errStr, "broken pipe") {
			return true
		}
		return false
	}

	// HTTP status codes that should be retried
	return isRetryable(statusCode)
}

// isRetryable checks if an HTTP status code should be retried
func isRetryable(statusCode int) bool {
	return statusCode == 429 || // Too Many Requests
		statusCode == 503 || // Service Unavailable
		statusCode == 504 // Gateway Timeout
}

// calculateBackoff computes the next backoff duration with exponential increase and jitter
func calculateBackoff(attempt int, config RetryConfig) time.Duration {
	// Exponential backoff: initialBackoff * (multiplier ^ attempt)
	backoff := float64(config.InitialBackoff) * math.Pow(config.Multiplier, float64(attempt))

	// Cap at max backoff
	if backoff > float64(config.MaxBackoff) {
		backoff = float64(config.MaxBackoff)
	}

	// Add jitter: ±25%
	jitterRange := backoff * 0.25
	jitter := (rand.Float64() * 2 * jitterRange) - jitterRange
	backoff += jitter

	// Ensure non-negative
	if backoff < 0 {
		backoff = 0
	}

	return time.Duration(backoff)
}

// handleRetryAfter parses the Retry-After header and returns the wait duration
// Returns the duration and true if successfully parsed, otherwise returns 0 and false
func handleRetryAfter(resp *http.Response) (time.Duration, bool) {
	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter == "" {
		return 0, false
	}

	// Trim whitespace
	retryAfter = strings.TrimSpace(retryAfter)
	if retryAfter == "" {
		return 0, false
	}

	// Try parsing as seconds (integer)
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
		// Cap at 5 minutes to prevent malicious headers
		duration := time.Duration(seconds) * time.Second
		if duration > 5*time.Minute {
			duration = 5 * time.Minute
		}
		return duration, true
	}

	// Try parsing as HTTP-date (RFC1123)
	if t, err := time.Parse(time.RFC1123, retryAfter); err == nil {
		duration := time.Until(t)
		if duration > 0 {
			if duration > 5*time.Minute {
				duration = 5 * time.Minute
			}
			return duration, true
		}
	}

	if t, err := time.Parse(time.RFC1123Z, retryAfter); err == nil {
		duration := time.Until(t)
		if duration > 0 {
			if duration > 5*time.Minute {
				duration = 5 * time.Minute
			}
			return duration, true
		}
	}

	return 0, false
}
