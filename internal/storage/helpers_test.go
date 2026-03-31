package storage

import (
	"testing"
)

func TestExtractNamespace(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		want       string
	}{
		{
			name:       "CVE format",
			identifier: "CVE-2023-1234",
			want:       "nvd",
		},
		{
			name:       "GHSA format",
			identifier: "GHSA-xxxx-yyyy-zzzz",
			want:       "github",
		},
		{
			name:       "RHSA format",
			identifier: "RHSA-2023:1234",
			want:       "redhat",
		},
		{
			name:       "DSA format",
			identifier: "DSA-5678-1",
			want:       "debian",
		},
		{
			name:       "Colon-separated with namespace",
			identifier: "alpine:3.18:CVE-2023-1234",
			want:       "alpine",
		},
		{
			name:       "Slash-separated with namespace",
			identifier: "debian/bookworm/CVE-2023-1234",
			want:       "debian",
		},
		{
			name:       "Unknown format",
			identifier: "UNKNOWN-123",
			want:       "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractNamespace(tt.identifier)
			if got != tt.want {
				t.Errorf("ExtractNamespace(%q) = %q, want %q", tt.identifier, got, tt.want)
			}
		})
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Clean filename",
			input: "CVE-2023-1234",
			want:  "CVE-2023-1234",
		},
		{
			name:  "With invalid characters",
			input: "test<>file|name?.txt",
			want:  "test__file_name_.txt",
		},
		{
			name:  "With quotes",
			input: "file\"with\"quotes",
			want:  "file_with_quotes",
		},
		{
			name:  "With null byte",
			input: "file\x00name",
			want:  "file_name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEnsureDir(t *testing.T) {
	t.Run("Create new directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		newDir := tmpDir + "/test/nested/dir"

		if err := EnsureDir(newDir); err != nil {
			t.Fatalf("EnsureDir failed: %v", err)
		}

		if !dirExists(newDir) {
			t.Error("Directory not created")
		}
	})

	t.Run("Empty path", func(t *testing.T) {
		if err := EnsureDir(""); err != nil {
			t.Errorf("EnsureDir(\"\") returned error: %v", err)
		}
	})

	t.Run("Existing directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		if err := EnsureDir(tmpDir); err != nil {
			t.Errorf("EnsureDir on existing directory returned error: %v", err)
		}
	})
}

func TestNew(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Create SQLite backend", func(t *testing.T) {
		config := Config{
			Type:      "sqlite",
			Path:      tmpDir + "/test.db",
			BatchSize: 1000,
		}

		backend, err := New(config)
		if err != nil {
			t.Fatalf("New(sqlite) failed: %v", err)
		}
		defer backend.Close(nil)

		if _, ok := backend.(*SQLiteBackend); !ok {
			t.Error("Backend is not SQLiteBackend")
		}
	})

	t.Run("Create flat-file backend", func(t *testing.T) {
		config := Config{
			Type: "flat-file",
			Path: tmpDir + "/results",
		}

		backend, err := New(config)
		if err != nil {
			t.Fatalf("New(flat-file) failed: %v", err)
		}
		defer backend.Close(nil)

		if _, ok := backend.(*FlatFileBackend); !ok {
			t.Error("Backend is not FlatFileBackend")
		}
	})

	t.Run("Unsupported backend type", func(t *testing.T) {
		config := Config{
			Type: "unsupported",
			Path: tmpDir + "/test",
		}

		_, err := New(config)
		if err == nil {
			t.Error("Expected error for unsupported backend type")
		}

		if _, ok := err.(*UnsupportedBackendError); !ok {
			t.Errorf("Expected UnsupportedBackendError, got %T", err)
		}
	})

	t.Run("Default batch size", func(t *testing.T) {
		config := Config{
			Type: "sqlite",
			Path: tmpDir + "/default-batch.db",
			// BatchSize not set
		}

		backend, err := New(config)
		if err != nil {
			t.Fatalf("New(sqlite) failed: %v", err)
		}
		defer backend.Close(nil)

		sqliteBackend, ok := backend.(*SQLiteBackend)
		if !ok {
			t.Fatal("Backend is not SQLiteBackend")
		}

		if sqliteBackend.batchSize != 10000 {
			t.Errorf("Default batch size = %d, want 10000", sqliteBackend.batchSize)
		}
	})
}
