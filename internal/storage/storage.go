// Package storage provides interfaces and implementations for storing vulnerability data.
// It supports both SQLite and flat-file backends with identical interfaces.
//
// For enrichment-engine compatibility, we re-export the unified Backend from pkg/storage.
package storage

import (
	vulnzstorage "github.com/shift/vulnz/pkg/storage"
)

// Backend defines storage operations for vulnerability data.
// Re-exported from pkg/storage for backward compatibility.
type Backend = vulnzstorage.Backend

// Envelope wraps vulnerability data with metadata.
// This structure is used for both SQLite and flat-file storage.
type Envelope struct {
	Schema     string      `json:"schema"`     // Schema URL (e.g., "https://schema.example.com/vuln/1.0")
	Identifier string      `json:"identifier"` // Unique ID (e.g., "CVE-2023-1234" or "alpine:3.18:CVE-2023-1234")
	Item       interface{} `json:"item"`       // Vulnerability payload (provider-specific data)
}

// Config for backend creation.
type Config struct {
	Type      string // "sqlite" or "flat-file"
	Path      string // Storage path (directory for flat-file, db file for sqlite)
	BatchSize int    // SQLite batch size (default: 1000)
}

// New creates an appropriate backend based on the configuration.
// Returns an error if the backend type is unsupported or initialization fails.
func New(config Config) (Backend, error) {
	switch config.Type {
	case "sqlite":
		batchSize := config.BatchSize
		if batchSize == 0 {
			batchSize = 1000
		}
		return NewSQLiteBackend(config.Path, batchSize)
	case "flat-file":
		batchSize := config.BatchSize
		if batchSize == 0 {
			batchSize = 500
		}
		return newFlatFileBackend(config.Path, batchSize)
	default:
		return nil, &UnsupportedBackendError{Type: config.Type}
	}
}

// UnsupportedBackendError is returned when an unknown backend type is requested.
type UnsupportedBackendError struct {
	Type string
}

func (e *UnsupportedBackendError) Error() string {
	return "unsupported backend type: " + e.Type
}
