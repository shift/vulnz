package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FlatFileBackend stores vulnerability data as individual JSON files.
// Files are organized into subdirectories based on namespace extracted from identifiers.
type FlatFileBackend struct {
	root      string // Results directory
	mu        sync.Mutex
	batch     []*Envelope
	batchSize int
}

// NewFlatFileBackend creates a new flat-file storage backend.
// The root directory will be created if it doesn't exist.
func NewFlatFileBackend(root string) (*FlatFileBackend, error) {
	return newFlatFileBackend(root, 1)
}

func newFlatFileBackend(root string, batchSize int) (*FlatFileBackend, error) {
	if err := EnsureDir(root); err != nil {
		return nil, fmt.Errorf("create root directory: %w", err)
	}

	return &FlatFileBackend{
		root:      root,
		batch:     make([]*Envelope, 0, batchSize),
		batchSize: batchSize,
	}, nil
}

// Write stores a vulnerability record as a JSON file.
// Records are accumulated in a batch and flushed when the batch size is reached.
// File structure: {root}/{namespace}/{id}.json
func (f *FlatFileBackend) Write(ctx context.Context, envelope *Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.batch = append(f.batch, envelope)

	if len(f.batch) >= f.batchSize {
		return f.flushBatchLocked(ctx)
	}

	return nil
}

func (f *FlatFileBackend) flushBatchLocked(ctx context.Context) error {
	if len(f.batch) == 0 {
		return nil
	}

	for _, envelope := range f.batch {
		namespace := ExtractNamespace(envelope.Identifier)
		var filePath string

		if strings.Contains(envelope.Identifier, string(os.PathSeparator)) {
			filePath = filepath.Join(f.root, envelope.Identifier+".json")
		} else {
			filePath = filepath.Join(f.root, namespace, SanitizeFilename(envelope.Identifier)+".json")
		}

		rel, err := filepath.Rel(f.root, filePath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("path traversal detected: %s", envelope.Identifier)
		}

		dir := filepath.Dir(filePath)
		if err := EnsureDir(dir); err != nil {
			return fmt.Errorf("create directory for %s: %w", envelope.Identifier, err)
		}

		data, err := json.MarshalIndent(envelope, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal envelope: %w", err)
		}

		tempFile := filePath + ".tmp"
		if err := os.WriteFile(tempFile, data, 0644); err != nil {
			return fmt.Errorf("write temp file: %w", err)
		}

		if err := os.Rename(tempFile, filePath); err != nil {
			os.Remove(tempFile)
			return fmt.Errorf("rename to final location: %w", err)
		}
	}

	f.batch = f.batch[:0]
	return nil
}

// Read retrieves a vulnerability record by ID.
func (f *FlatFileBackend) Read(ctx context.Context, id string) (*Envelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.flushBatchLocked(ctx); err != nil {
		return nil, err
	}

	filePath := f.findFilePath(id)
	if filePath == "" {
		return nil, fmt.Errorf("record not found: %s", id)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	return &envelope, nil
}

// findFilePath attempts to locate the file for a given identifier.
// It tries multiple possible locations based on namespace extraction.
func (f *FlatFileBackend) findFilePath(id string) string {
	// Try direct path first
	if strings.Contains(id, string(os.PathSeparator)) {
		directPath := filepath.Join(f.root, id+".json")
		if fileExists(directPath) {
			return directPath
		}
	}

	// Try namespace-based path
	namespace := ExtractNamespace(id)
	namespacePath := filepath.Join(f.root, namespace, SanitizeFilename(id)+".json")
	if fileExists(namespacePath) {
		return namespacePath
	}

	return ""
}

// List returns all vulnerability IDs by walking the directory tree.
func (f *FlatFileBackend) List(ctx context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.flushBatchLocked(ctx); err != nil {
		return nil, err
	}

	var ids []string

	err := filepath.Walk(f.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		relPath, err := filepath.Rel(f.root, path)
		if err != nil {
			return fmt.Errorf("get relative path: %w", err)
		}

		id := strings.TrimSuffix(relPath, ".json")
		id = filepath.ToSlash(id)

		ids = append(ids, id)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	return ids, nil
}

// Count returns the total number of records by counting .json files.
func (f *FlatFileBackend) Count(ctx context.Context) (int, error) {
	ids, err := f.List(ctx)
	if err != nil {
		return 0, err
	}
	return len(ids), nil
}

// Close finalizes storage by flushing any remaining batch.
func (f *FlatFileBackend) Close(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushBatchLocked(ctx)
}
