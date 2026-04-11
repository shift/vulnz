package pbt

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/shift/vulnz/internal/storage"
	"pgregory.net/rapid"
)

func TestSQLiteWriteReadRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tmpDir, err := os.MkdirTemp("", "pbt-sqlite-*")
		assert(t, err == nil, "tempdir failed")
		defer os.RemoveAll(tmpDir)

		dbPath := filepath.Join(tmpDir, "test.db")

		backend, err := storage.NewSQLiteBackend(dbPath, 1)
		assert(t, err == nil, "NewSQLiteBackend failed")
		defer backend.Close(context.Background())

		envelope := rapidEnvelope().Draw(t, "env")

		err = backend.Write(context.Background(), envelope)
		assert(t, err == nil, "Write failed")

		read, err := backend.Read(context.Background(), envelope.Identifier)
		assert(t, err == nil, "Read failed")
		assert(t, read.Identifier == envelope.Identifier, "Identifier mismatch")
		assert(t, read.Schema == envelope.Schema, "Schema mismatch")
	})
}

func TestFlatFileWriteReadRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tmpDir, err := os.MkdirTemp("", "pbt-flatfile-*")
		assert(t, err == nil, "tempdir failed")
		defer os.RemoveAll(tmpDir)

		backend, err := storage.NewFlatFileBackend(tmpDir)
		assert(t, err == nil, "NewFlatFileBackend failed")
		defer backend.Close(context.Background())

		envelope := rapidEnvelope().Draw(t, "env")

		err = backend.Write(context.Background(), envelope)
		assert(t, err == nil, "Write failed")

		read, err := backend.Read(context.Background(), envelope.Identifier)
		assert(t, err == nil, "Read failed")
		assert(t, read.Identifier == envelope.Identifier, "Identifier mismatch")
		assert(t, read.Schema == envelope.Schema, "Schema mismatch")
	})
}

func TestFlatFileJSONRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tmpDir, err := os.MkdirTemp("", "pbt-flatjson-*")
		assert(t, err == nil, "tempdir failed")
		defer os.RemoveAll(tmpDir)

		backend, err := storage.NewFlatFileBackend(tmpDir)
		assert(t, err == nil, "NewFlatFileBackend failed")

		envelope := rapidEnvelope().Draw(t, "env")

		err = backend.Write(context.Background(), envelope)
		assert(t, err == nil, "Write failed")

		err = backend.Close(context.Background())
		assert(t, err == nil, "Close failed")

		files, err := os.ReadDir(tmpDir)
		assert(t, err == nil, "ReadDir failed")
		assert(t, len(files) > 0, "no files written")

		for _, f := range files {
			if f.IsDir() {
				subFiles, err := os.ReadDir(filepath.Join(tmpDir, f.Name()))
				assert(t, err == nil, "ReadDir subdir failed")
				for _, sf := range subFiles {
					data, err := os.ReadFile(filepath.Join(tmpDir, f.Name(), sf.Name()))
					assert(t, err == nil, "ReadFile failed")

					var decoded storage.Envelope
					err = json.Unmarshal(data, &decoded)
					assert(t, err == nil, "Unmarshal failed")
					assert(t, decoded.Identifier != "", "empty identifier after roundtrip")
				}
			}
		}
	})
}

func TestConcurrentWriteSafety(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tmpDir, err := os.MkdirTemp("", "pbt-concurrent-*")
		assert(t, err == nil, "tempdir failed")
		defer os.RemoveAll(tmpDir)

		dbPath := filepath.Join(tmpDir, "test.db")

		backend, err := storage.NewSQLiteBackend(dbPath, 1)
		assert(t, err == nil, "NewSQLiteBackend failed")
		defer backend.Close(context.Background())

		ctx := context.Background()
		numWriters := rapid.IntRange(2, 10).Draw(t, "writers")
		envelopes := make([]*storage.Envelope, numWriters)
		for i := range envelopes {
			env := rapidEnvelope().Draw(t, "env")
			env.Identifier = env.Identifier + "-" + randomSuffix(i)
			envelopes[i] = env
		}

		var wg sync.WaitGroup
		errCh := make(chan error, numWriters)

		for _, env := range envelopes {
			wg.Add(1)
			go func(e *storage.Envelope) {
				defer wg.Done()
				if err := backend.Write(ctx, e); err != nil {
					errCh <- err
				}
			}(env)
		}

		wg.Wait()
		close(errCh)

		for err := range errCh {
			assert(t, err == nil, "concurrent write error")
		}

		count, err := backend.Count(ctx)
		assert(t, err == nil, "Count failed")
		assert(t, count >= numWriters, "count mismatch after concurrent writes")
	})
}

func rapidEnvelope() *rapid.Generator[*storage.Envelope] {
	return rapid.Custom(func(t *rapid.T) *storage.Envelope {
		id := rapid.SampledFrom([]string{
			"CVE-2023-0001",
			"CVE-2023-0002",
			"GHSA-xxxx-yyyy-zzzz",
			"RHSA-2023-0001",
			"alpine:3.18:CVE-2023-5678",
			"debian:bookworm:CVE-2023-9999",
		}).Draw(t, "id")

		schema := rapid.StringMatching("https?://schema\\..*").Draw(t, "schema")
		if schema == "" {
			schema = "https://schema.example.com/vuln/1.0"
		}

		return &storage.Envelope{
			Schema:     schema,
			Identifier: id,
			Item: rapid.MapOf(
				rapid.StringN(1, 20, 20),
				rapid.String(),
			).Draw(t, "item"),
		}
	})
}

func randomSuffix(i int) string {
	suffixes := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	if i < len(suffixes) {
		return suffixes[i]
	}
	return "x"
}
