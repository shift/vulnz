package storage

import (
	"context"
	"testing"
)

// testBackend runs a comprehensive test suite against any Backend implementation.
// This ensures both SQLite and flat-file backends provide identical behavior.
func testBackend(t *testing.T, backend Backend) {
	ctx := context.Background()

	t.Run("Write and Read", func(t *testing.T) {
		envelope := &Envelope{
			Schema:     "https://schema.example.com/vuln/1.0",
			Identifier: "CVE-2023-1234",
			Item: map[string]interface{}{
				"severity":    "HIGH",
				"description": "Buffer overflow vulnerability",
			},
		}

		// Write
		err := backend.Write(ctx, envelope)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		// Read
		retrieved, err := backend.Read(ctx, "CVE-2023-1234")
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		if retrieved.Schema != envelope.Schema {
			t.Errorf("Schema mismatch: got %s, want %s", retrieved.Schema, envelope.Schema)
		}
		if retrieved.Identifier != envelope.Identifier {
			t.Errorf("Identifier mismatch: got %s, want %s", retrieved.Identifier, envelope.Identifier)
		}
	})

	t.Run("Write Multiple Records", func(t *testing.T) {
		records := []string{"CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"}

		for _, id := range records {
			envelope := &Envelope{
				Schema:     "https://schema.example.com/vuln/1.0",
				Identifier: id,
				Item: map[string]interface{}{
					"severity": "MEDIUM",
				},
			}
			if err := backend.Write(ctx, envelope); err != nil {
				t.Fatalf("Write %s failed: %v", id, err)
			}
		}

		// Count
		count, err := backend.Count(ctx)
		if err != nil {
			t.Fatalf("Count failed: %v", err)
		}
		if count < len(records) {
			t.Errorf("Count mismatch: got %d, want at least %d", count, len(records))
		}
	})

	t.Run("List All Records", func(t *testing.T) {
		ids, err := backend.List(ctx)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}

		if len(ids) == 0 {
			t.Error("List returned no records")
		}
	})

	t.Run("Read Non-Existent Record", func(t *testing.T) {
		_, err := backend.Read(ctx, "CVE-9999-9999")
		if err == nil {
			t.Error("Expected error reading non-existent record")
		}
	})

	t.Run("Write with Namespace", func(t *testing.T) {
		envelope := &Envelope{
			Schema:     "https://schema.example.com/vuln/1.0",
			Identifier: "alpine:3.18:CVE-2023-5678",
			Item: map[string]interface{}{
				"package": "openssl",
			},
		}

		if err := backend.Write(ctx, envelope); err != nil {
			t.Fatalf("Write with namespace failed: %v", err)
		}

		retrieved, err := backend.Read(ctx, "alpine:3.18:CVE-2023-5678")
		if err != nil {
			t.Fatalf("Read with namespace failed: %v", err)
		}

		if retrieved.Identifier != envelope.Identifier {
			t.Errorf("Identifier mismatch: got %s, want %s", retrieved.Identifier, envelope.Identifier)
		}
	})
}

// TestBackendInterface ensures both backends implement the Backend interface correctly.
func TestBackendInterface(t *testing.T) {
	var _ Backend = (*SQLiteBackend)(nil)
	var _ Backend = (*FlatFileBackend)(nil)
}
