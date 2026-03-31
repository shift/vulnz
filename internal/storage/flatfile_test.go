package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlatFileBackend(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "vulnz-flatfile-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	t.Run("NewFlatFileBackend", func(t *testing.T) {
		backend, err := NewFlatFileBackend(tmpDir)
		if err != nil {
			t.Fatalf("NewFlatFileBackend failed: %v", err)
		}

		if backend.root != tmpDir {
			t.Errorf("Root path mismatch: got %s, want %s", backend.root, tmpDir)
		}
	})

	t.Run("Backend Operations", func(t *testing.T) {
		backend, err := NewFlatFileBackend(tmpDir)
		if err != nil {
			t.Fatalf("NewFlatFileBackend failed: %v", err)
		}

		testBackend(t, backend)
		backend.Close(context.Background())
	})

	t.Run("Nested Directory Structure", func(t *testing.T) {
		backend, err := NewFlatFileBackend(tmpDir)
		if err != nil {
			t.Fatalf("NewFlatFileBackend failed: %v", err)
		}

		ctx := context.Background()

		// Write record with namespace
		envelope := &Envelope{
			Schema:     "https://schema.example.com/vuln/1.0",
			Identifier: "alpine:3.18:CVE-2023-1234",
			Item: map[string]interface{}{
				"package": "openssl",
			},
		}

		if err := backend.Write(ctx, envelope); err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		// Verify file was created in namespace directory
		namespace := ExtractNamespace(envelope.Identifier)
		expectedDir := filepath.Join(tmpDir, namespace)
		if !dirExists(expectedDir) {
			t.Errorf("Namespace directory not created: %s", expectedDir)
		}

		backend.Close(ctx)
	})

	t.Run("Atomic Writes", func(t *testing.T) {
		backend, err := NewFlatFileBackend(tmpDir)
		if err != nil {
			t.Fatalf("NewFlatFileBackend failed: %v", err)
		}

		ctx := context.Background()

		envelope := &Envelope{
			Schema:     "https://schema.example.com/vuln/1.0",
			Identifier: "ATOMIC-TEST",
			Item: map[string]interface{}{
				"data": "test",
			},
		}

		if err := backend.Write(ctx, envelope); err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		// Verify no temp files remain
		matches, err := filepath.Glob(filepath.Join(tmpDir, "**/*.tmp"))
		if err != nil {
			t.Fatalf("Glob failed: %v", err)
		}
		if len(matches) > 0 {
			t.Errorf("Temp files not cleaned up: %v", matches)
		}

		backend.Close(ctx)
	})

	t.Run("Pretty Print JSON", func(t *testing.T) {
		backend, err := NewFlatFileBackend(tmpDir)
		if err != nil {
			t.Fatalf("NewFlatFileBackend failed: %v", err)
		}

		ctx := context.Background()

		envelope := &Envelope{
			Schema:     "https://schema.example.com/vuln/1.0",
			Identifier: "PRETTY-TEST",
			Item: map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
		}

		if err := backend.Write(ctx, envelope); err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		// Read file and verify it's pretty-printed
		filePath := filepath.Join(tmpDir, "unknown", "PRETTY-TEST.json")
		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("Read file failed: %v", err)
		}

		content := string(data)
		// Pretty-printed JSON should have newlines and indentation
		if !strings.Contains(content, "\n") || !strings.Contains(content, "  ") {
			t.Error("JSON not pretty-printed")
		}

		backend.Close(ctx)
	})

	t.Run("Overwrite Existing File", func(t *testing.T) {
		backend, err := NewFlatFileBackend(tmpDir)
		if err != nil {
			t.Fatalf("NewFlatFileBackend failed: %v", err)
		}

		ctx := context.Background()

		// Write first version
		envelope1 := &Envelope{
			Schema:     "https://schema.example.com/vuln/1.0",
			Identifier: "OVERWRITE-TEST",
			Item: map[string]interface{}{
				"version": 1,
			},
		}
		if err := backend.Write(ctx, envelope1); err != nil {
			t.Fatalf("First write failed: %v", err)
		}

		// Write second version
		envelope2 := &Envelope{
			Schema:     "https://schema.example.com/vuln/1.0",
			Identifier: "OVERWRITE-TEST",
			Item: map[string]interface{}{
				"version": 2,
			},
		}
		if err := backend.Write(ctx, envelope2); err != nil {
			t.Fatalf("Second write failed: %v", err)
		}

		// Read and verify latest version
		retrieved, err := backend.Read(ctx, "OVERWRITE-TEST")
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		itemMap, ok := retrieved.Item.(map[string]interface{})
		if !ok {
			t.Fatalf("Item type assertion failed")
		}

		version, ok := itemMap["version"].(float64)
		if !ok || version != 2 {
			t.Errorf("Version mismatch: got %v, want 2", itemMap["version"])
		}

		backend.Close(ctx)
	})

	t.Run("Concurrent Writes Different Files", func(t *testing.T) {
		backend, err := NewFlatFileBackend(tmpDir)
		if err != nil {
			t.Fatalf("NewFlatFileBackend failed: %v", err)
		}

		ctx := context.Background()
		done := make(chan bool)

		// Launch multiple goroutines writing different files
		for i := 0; i < 5; i++ {
			go func(id int) {
				envelope := &Envelope{
					Schema:     "https://schema.example.com/vuln/1.0",
					Identifier: "CONCURRENT-FILE-" + string(rune('A'+id)),
					Item: map[string]interface{}{
						"goroutine": id,
					},
				}
				if err := backend.Write(ctx, envelope); err != nil {
					t.Errorf("Concurrent write failed: %v", err)
				}
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 5; i++ {
			<-done
		}

		// Verify all files were written
		count, err := backend.Count(ctx)
		if err != nil {
			t.Fatalf("Count failed: %v", err)
		}
		if count < 5 {
			t.Errorf("Count mismatch: got %d, want at least 5", count)
		}

		backend.Close(ctx)
	})
}

func TestFlatFileBackend_PathWithSeparators(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vulnz-flatfile-path-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, err := NewFlatFileBackend(tmpDir)
	if err != nil {
		t.Fatalf("NewFlatFileBackend failed: %v", err)
	}

	ctx := context.Background()

	// Write record with path separators in identifier
	envelope := &Envelope{
		Schema:     "https://schema.example.com/vuln/1.0",
		Identifier: "debian/bookworm/CVE-2023-5678",
		Item: map[string]interface{}{
			"package": "nginx",
		},
	}

	if err := backend.Write(ctx, envelope); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify nested directories were created
	expectedPath := filepath.Join(tmpDir, "debian", "bookworm", "CVE-2023-5678.json")
	if !fileExists(expectedPath) {
		t.Errorf("File not created at expected path: %s", expectedPath)
	}

	// Read and verify
	retrieved, err := backend.Read(ctx, "debian/bookworm/CVE-2023-5678")
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if retrieved.Identifier != envelope.Identifier {
		t.Errorf("Identifier mismatch: got %s, want %s", retrieved.Identifier, envelope.Identifier)
	}

	backend.Close(ctx)
}
