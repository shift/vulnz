package http

import "time"

// Config defines HTTP client configuration
type Config struct {
	// Timeout for individual HTTP requests
	Timeout time.Duration
	// MaxRetries is the maximum number of retry attempts
	MaxRetries int
	// InitialBackoff is the initial backoff duration for retries
	InitialBackoff time.Duration
	// MaxBackoff is the maximum backoff duration
	MaxBackoff time.Duration
	// RateLimitRPS is requests per second per host
	RateLimitRPS int
	// MaxConnsPerHost is the maximum connections per host
	MaxConnsPerHost int
	// UserAgent is the User-Agent header value
	UserAgent string
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		Timeout:         30 * time.Second,
		MaxRetries:      5,
		InitialBackoff:  1 * time.Second,
		MaxBackoff:      60 * time.Second,
		RateLimitRPS:    10,
		MaxConnsPerHost: 10,
		UserAgent:       "vulnz-go/1.0",
	}
}
