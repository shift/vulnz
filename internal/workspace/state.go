// Package workspace manages provider-specific directories, state persistence, and file locking.
package workspace

import "time"

// State represents workspace metadata that tracks the last provider run.
// It is persisted to metadata.json and includes information about what was
// processed, where results are stored, and the integrity of result files.
type State struct {
	// Provider is the name of the provider that owns this workspace
	Provider string `json:"provider"`

	// URLs contains the list of source URLs that were fetched during the run
	URLs []string `json:"urls"`

	// Store indicates the storage backend used: "sqlite" or "flat-file"
	Store string `json:"store"`

	// Timestamp is when the provider last completed successfully
	Timestamp time.Time `json:"timestamp"`

	// Version is the state schema version (for future migrations)
	Version int `json:"version"`

	// DistributionVersion is the version of the data distribution
	DistributionVersion int `json:"distribution_version"`

	// Listing contains metadata about the checksums file
	Listing *File `json:"listing,omitempty"`

	// Stale indicates whether the workspace needs to be updated
	Stale bool `json:"stale"`

	// Processor identifies the tool and version that created this state
	Processor string `json:"processor,omitempty"`
}

// File represents metadata about a file in the workspace.
type File struct {
	// Path is the relative path from the workspace root
	Path string `json:"path"`

	// Checksum is the xxHash64 hash of the file contents
	Checksum string `json:"checksum"`

	// Algorithm is the hash algorithm used (always "xxh64")
	Algorithm string `json:"algorithm"`

	// LastModified is when the file was last modified
	LastModified time.Time `json:"last_modified"`
}
