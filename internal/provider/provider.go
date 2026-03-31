// Package provider defines the core interfaces and types for vulnerability data providers.
package provider

import (
	"context"
	"time"
)

// Provider defines the interface all vulnerability data providers must implement.
// Each provider is responsible for fetching vulnerability data from a specific source,
// transforming it to a standard format, and writing results to storage.
type Provider interface {
	// Name returns the unique provider identifier (e.g., "alpine", "ubuntu", "nvd").
	// This name is used for workspace directories, configuration keys, and logging.
	Name() string

	// Update fetches and processes vulnerability data.
	// The lastUpdated parameter is nil on the first run, otherwise it contains
	// the timestamp of the last successful run. Providers can use this to implement
	// incremental updates.
	//
	// Returns:
	//   - urls: List of URLs that were fetched during the update
	//   - count: Number of vulnerability records processed
	//   - err: Any error encountered during the update
	Update(ctx context.Context, lastUpdated *time.Time) (urls []string, count int, err error)
}

// Metadata contains provider information and is used for documentation and discovery.
type Metadata struct {
	Name        string // Provider name
	Description string // Human-readable description
	Version     string // Provider version
	Homepage    string // URL to provider documentation or source
}

// MetadataProvider is an optional interface that providers can implement
// to expose metadata about themselves.
type MetadataProvider interface {
	Provider
	Metadata() Metadata
}

// TagsProvider is an optional interface that providers can implement
// to expose classification tags (e.g., "os", "language", "cve").
type TagsProvider interface {
	Provider
	Tags() []string
}
