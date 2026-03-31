package provider

import (
	"log/slog"
	"time"
)

// Config is the base configuration all providers receive.
// It provides access to common resources like workspace, storage, HTTP client, and logging.
type Config struct {
	Name      string        // Provider name
	Workspace string        // Root workspace directory for this provider
	Storage   StorageConfig // Storage backend configuration
	HTTP      HTTPConfig    // HTTP client configuration
	Logger    *slog.Logger  // Structured logger instance
}

// StorageConfig configures the storage backend for vulnerability data.
type StorageConfig struct {
	Type string // Storage type: "sqlite" or "flat-file"
	Path string // Path to storage location (directory or database file)
}

// HTTPConfig configures the HTTP client used for fetching vulnerability data.
type HTTPConfig struct {
	Timeout      time.Duration // Request timeout
	MaxRetries   int           // Maximum number of retry attempts
	RateLimitRPS int           // Rate limit in requests per second
	UserAgent    string        // User agent string for HTTP requests
}

// DefaultHTTPConfig returns sensible defaults for HTTP client configuration.
func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Timeout:      30 * time.Second,
		MaxRetries:   5,
		RateLimitRPS: 10,
		UserAgent:    "vulnz-go/1.0",
	}
}
