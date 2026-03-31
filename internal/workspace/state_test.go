package workspace

import (
	"encoding/json"
	"testing"
	"time"
)

func TestState_JSONSerialization(t *testing.T) {
	now := time.Now().UTC()

	state := &State{
		Provider:            "alpine",
		URLs:                []string{"http://example.com/data1.json", "http://example.com/data2.json"},
		Store:               "sqlite",
		Timestamp:           now,
		Version:             1,
		DistributionVersion: 2,
		Stale:               false,
		Processor:           "vulnz-go@1.0.0",
		Listing: &File{
			Path:         "checksums",
			Checksum:     "a1b2c3d4e5f6g7h8",
			Algorithm:    "xxh64",
			LastModified: now,
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal back
	var decoded State
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify fields
	if decoded.Provider != state.Provider {
		t.Errorf("Provider mismatch: got %s, want %s", decoded.Provider, state.Provider)
	}
	if decoded.Store != state.Store {
		t.Errorf("Store mismatch: got %s, want %s", decoded.Store, state.Store)
	}
	if len(decoded.URLs) != len(state.URLs) {
		t.Errorf("URLs length mismatch: got %d, want %d", len(decoded.URLs), len(state.URLs))
	}
	if decoded.Version != state.Version {
		t.Errorf("Version mismatch: got %d, want %d", decoded.Version, state.Version)
	}
	if decoded.DistributionVersion != state.DistributionVersion {
		t.Errorf("DistributionVersion mismatch: got %d, want %d", decoded.DistributionVersion, state.DistributionVersion)
	}
	if decoded.Stale != state.Stale {
		t.Errorf("Stale mismatch: got %v, want %v", decoded.Stale, state.Stale)
	}
	if decoded.Processor != state.Processor {
		t.Errorf("Processor mismatch: got %s, want %s", decoded.Processor, state.Processor)
	}

	// Verify listing
	if decoded.Listing == nil {
		t.Fatal("Listing is nil after unmarshal")
	}
	if decoded.Listing.Path != state.Listing.Path {
		t.Errorf("Listing.Path mismatch: got %s, want %s", decoded.Listing.Path, state.Listing.Path)
	}
	if decoded.Listing.Checksum != state.Listing.Checksum {
		t.Errorf("Listing.Checksum mismatch: got %s, want %s", decoded.Listing.Checksum, state.Listing.Checksum)
	}
	if decoded.Listing.Algorithm != state.Listing.Algorithm {
		t.Errorf("Listing.Algorithm mismatch: got %s, want %s", decoded.Listing.Algorithm, state.Listing.Algorithm)
	}
}

func TestState_WithoutListing(t *testing.T) {
	state := &State{
		Provider:            "debian",
		URLs:                []string{"http://example.com/data.json"},
		Store:               "flat-file",
		Timestamp:           time.Now().UTC(),
		Version:             1,
		DistributionVersion: 1,
		Stale:               true,
		Listing:             nil, // No listing
	}

	// Marshal to JSON
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal back
	var decoded State
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify listing is nil
	if decoded.Listing != nil {
		t.Error("Listing should be nil")
	}
}

func TestFile_JSONSerialization(t *testing.T) {
	now := time.Now().UTC()

	file := &File{
		Path:         "results/CVE-2023-1234.json",
		Checksum:     "1234567890abcdef",
		Algorithm:    "xxh64",
		LastModified: now,
	}

	// Marshal to JSON
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal back
	var decoded File
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify fields
	if decoded.Path != file.Path {
		t.Errorf("Path mismatch: got %s, want %s", decoded.Path, file.Path)
	}
	if decoded.Checksum != file.Checksum {
		t.Errorf("Checksum mismatch: got %s, want %s", decoded.Checksum, file.Checksum)
	}
	if decoded.Algorithm != file.Algorithm {
		t.Errorf("Algorithm mismatch: got %s, want %s", decoded.Algorithm, file.Algorithm)
	}
	// Time comparison with tolerance for JSON serialization
	if decoded.LastModified.Unix() != file.LastModified.Unix() {
		t.Errorf("LastModified mismatch: got %v, want %v", decoded.LastModified, file.LastModified)
	}
}

func TestState_EmptyURLs(t *testing.T) {
	state := &State{
		Provider:  "test",
		URLs:      []string{}, // Empty URLs
		Store:     "sqlite",
		Timestamp: time.Now().UTC(),
		Version:   1,
	}

	// Marshal to JSON
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal back
	var decoded State
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify empty URLs are preserved (not nil)
	if decoded.URLs == nil {
		t.Error("URLs should be empty slice, not nil")
	}
	if len(decoded.URLs) != 0 {
		t.Errorf("URLs should be empty, got length %d", len(decoded.URLs))
	}
}
