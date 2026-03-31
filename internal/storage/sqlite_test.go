package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLiteBackend(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "vulnz-sqlite-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")

	t.Run("NewSQLiteBackend", func(t *testing.T) {
		backend, err := NewSQLiteBackend(dbPath, 100)
		if err != nil {
			t.Fatalf("NewSQLiteBackend failed: %v", err)
		}
		defer backend.Close(context.Background())

		if backend.batchSize != 100 {
			t.Errorf("Batch size mismatch: got %d, want 100", backend.batchSize)
		}
	})

	t.Run("Backend Operations", func(t *testing.T) {
		backend, err := NewSQLiteBackend(dbPath, 10)
		if err != nil {
			t.Fatalf("NewSQLiteBackend failed: %v", err)
		}
		defer backend.Close(context.Background())

		testBackend(t, backend)
	})

	t.Run("Batch Flushing", func(t *testing.T) {
		backend, err := NewSQLiteBackend(dbPath, 5)
		if err != nil {
			t.Fatalf("NewSQLiteBackend failed: %v", err)
		}
		defer backend.Close(context.Background())

		ctx := context.Background()

		// Write exactly batch size records
		for i := 0; i < 5; i++ {
			envelope := &Envelope{
				Schema:     "https://schema.example.com/vuln/1.0",
				Identifier: "BATCH-" + string(rune('A'+i)),
				Item:       map[string]interface{}{"test": true},
			}
			if err := backend.Write(ctx, envelope); err != nil {
				t.Fatalf("Write failed: %v", err)
			}
		}

		// Batch should be auto-flushed
		if len(backend.batch) != 0 {
			t.Errorf("Batch not flushed: %d records remaining", len(backend.batch))
		}

		// Verify records were written
		count, err := backend.Count(ctx)
		if err != nil {
			t.Fatalf("Count failed: %v", err)
		}
		if count < 5 {
			t.Errorf("Count mismatch: got %d, want at least 5", count)
		}
	})

	t.Run("Close Flushes Remaining Batch", func(t *testing.T) {
		backend, err := NewSQLiteBackend(dbPath, 1000)
		if err != nil {
			t.Fatalf("NewSQLiteBackend failed: %v", err)
		}

		ctx := context.Background()

		// Write less than batch size
		for i := 0; i < 3; i++ {
			envelope := &Envelope{
				Schema:     "https://schema.example.com/vuln/1.0",
				Identifier: "CLOSE-TEST-" + string(rune('A'+i)),
				Item:       map[string]interface{}{"test": true},
			}
			if err := backend.Write(ctx, envelope); err != nil {
				t.Fatalf("Write failed: %v", err)
			}
		}

		// Close should flush remaining batch
		if err := backend.Close(ctx); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Verify database was moved to final location
		if !fileExists(dbPath) {
			t.Error("Database not moved to final location")
		}
	})

	t.Run("Concurrent Writes", func(t *testing.T) {
		backend, err := NewSQLiteBackend(dbPath, 50)
		if err != nil {
			t.Fatalf("NewSQLiteBackend failed: %v", err)
		}
		defer backend.Close(context.Background())

		ctx := context.Background()
		done := make(chan bool)

		// Launch multiple goroutines writing concurrently
		for i := 0; i < 10; i++ {
			go func(id int) {
				for j := 0; j < 5; j++ {
					envelope := &Envelope{
						Schema:     "https://schema.example.com/vuln/1.0",
						Identifier: "CONCURRENT-" + string(rune('A'+id)) + string(rune('0'+j)),
						Item:       map[string]interface{}{"goroutine": id, "iteration": j},
					}
					if err := backend.Write(ctx, envelope); err != nil {
						t.Errorf("Concurrent write failed: %v", err)
					}
				}
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		// Verify all records were written
		count, err := backend.Count(ctx)
		if err != nil {
			t.Fatalf("Count failed: %v", err)
		}
		if count < 50 {
			t.Errorf("Count mismatch after concurrent writes: got %d, want at least 50", count)
		}
	})

	t.Run("Write After Close Error", func(t *testing.T) {
		backend, err := NewSQLiteBackend(dbPath, 100)
		if err != nil {
			t.Fatalf("NewSQLiteBackend failed: %v", err)
		}

		ctx := context.Background()
		backend.Close(ctx)

		// Try to write after close
		envelope := &Envelope{
			Schema:     "https://schema.example.com/vuln/1.0",
			Identifier: "AFTER-CLOSE",
			Item:       map[string]interface{}{"test": true},
		}
		err = backend.Write(ctx, envelope)
		if err == nil {
			t.Error("Expected error writing after close")
		}
	})
}

func TestSQLiteBackend_WALMode(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vulnz-sqlite-wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "wal-test.db")
	backend, err := NewSQLiteBackend(dbPath, 100)
	if err != nil {
		t.Fatalf("NewSQLiteBackend failed: %v", err)
	}
	defer backend.Close(context.Background())

	// Verify WAL mode is enabled
	var journalMode string
	err = backend.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	if err != nil {
		t.Fatalf("Query journal_mode failed: %v", err)
	}

	if journalMode != "wal" {
		t.Errorf("Journal mode mismatch: got %s, want wal", journalMode)
	}
}
