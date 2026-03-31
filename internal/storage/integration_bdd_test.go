package storage_test

import (
	"context"
	"fmt"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/storage"
)

var _ = Describe("Storage Backend Integration", func() {
	var (
		tempDir string
		ctx     context.Context
	)

	BeforeEach(func() {
		tempDir = GinkgoT().TempDir()
		ctx = context.Background()
	})

	Describe("Backend factory", func() {
		Context("when creating SQLite backend", func() {
			It("should create backend successfully", func() {
				config := storage.Config{
					Type:      "sqlite",
					Path:      filepath.Join(tempDir, "test.db"),
					BatchSize: 100,
				}

				backend, err := storage.New(config)
				Expect(err).NotTo(HaveOccurred())
				Expect(backend).NotTo(BeNil())

				defer backend.Close(ctx)
			})

			It("should use default batch size when not specified", func() {
				config := storage.Config{
					Type: "sqlite",
					Path: filepath.Join(tempDir, "test.db"),
					// BatchSize is 0, should use default
				}

				backend, err := storage.New(config)
				Expect(err).NotTo(HaveOccurred())
				Expect(backend).NotTo(BeNil())

				defer backend.Close(ctx)
			})
		})

		Context("when creating flat-file backend", func() {
			It("should create backend successfully", func() {
				config := storage.Config{
					Type: "flat-file",
					Path: filepath.Join(tempDir, "results"),
				}

				backend, err := storage.New(config)
				Expect(err).NotTo(HaveOccurred())
				Expect(backend).NotTo(BeNil())

				defer backend.Close(ctx)
			})
		})

		Context("when using invalid backend type", func() {
			It("should return UnsupportedBackendError", func() {
				config := storage.Config{
					Type: "invalid-backend",
					Path: tempDir,
				}

				backend, err := storage.New(config)
				Expect(err).To(HaveOccurred())
				Expect(backend).To(BeNil())

				var unsupportedErr *storage.UnsupportedBackendError
				Expect(err).To(BeAssignableToTypeOf(unsupportedErr))
				Expect(err.Error()).To(ContainSubstring("invalid-backend"))
			})

			It("should handle empty backend type", func() {
				config := storage.Config{
					Type: "",
					Path: tempDir,
				}

				backend, err := storage.New(config)
				Expect(err).To(HaveOccurred())
				Expect(backend).To(BeNil())
			})
		})
	})

	Describe("Backend comparison", func() {
		var (
			sqliteBackend   storage.Backend
			flatfileBackend storage.Backend
			testEnvelopes   []*storage.Envelope
		)

		BeforeEach(func() {
			// Create test data
			testEnvelopes = []*storage.Envelope{
				{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-0001",
					Item: map[string]interface{}{
						"severity":    "HIGH",
						"description": "Test vulnerability 1",
					},
				},
				{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-0002",
					Item: map[string]interface{}{
						"severity":    "MEDIUM",
						"description": "Test vulnerability 2",
					},
				},
				{
					Schema:     "https://example.com/schema/v1",
					Identifier: "GHSA-abcd-efgh-ijkl",
					Item: map[string]interface{}{
						"ecosystem": "npm",
						"package":   "lodash",
					},
				},
				{
					Schema:     "https://example.com/schema/v1",
					Identifier: "alpine:3.18:CVE-2023-0003",
					Item: map[string]interface{}{
						"package": "openssl",
						"version": "1.1.1",
					},
				},
			}

			// Create backends
			var err error
			sqliteBackend, err = storage.NewSQLiteBackend(
				filepath.Join(tempDir, "test.db"),
				100,
			)
			Expect(err).NotTo(HaveOccurred())

			flatfileBackend, err = storage.NewFlatFileBackend(
				filepath.Join(tempDir, "results"),
			)
			Expect(err).NotTo(HaveOccurred())

			// Write test data to both backends
			for _, envelope := range testEnvelopes {
				err = sqliteBackend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())

				err = flatfileBackend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())
			}

			// Close and reopen SQLite to ensure persistence
			err = sqliteBackend.Close(ctx)
			Expect(err).NotTo(HaveOccurred())

			sqliteBackend, err = storage.NewSQLiteBackend(
				filepath.Join(tempDir, "test.db"),
				100,
			)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if sqliteBackend != nil {
				sqliteBackend.Close(ctx)
			}
			if flatfileBackend != nil {
				flatfileBackend.Close(ctx)
			}
		})

		Context("with identical test data", func() {
			It("should produce same count for both backends", func() {
				sqliteCount, err := sqliteBackend.Count(ctx)
				Expect(err).NotTo(HaveOccurred())

				flatfileCount, err := flatfileBackend.Count(ctx)
				Expect(err).NotTo(HaveOccurred())

				Expect(sqliteCount).To(Equal(flatfileCount))
				Expect(sqliteCount).To(Equal(4))
			})

			It("should produce same ID lists", func() {
				sqliteIDs, err := sqliteBackend.List(ctx)
				Expect(err).NotTo(HaveOccurred())

				flatfileIDs, err := flatfileBackend.List(ctx)
				Expect(err).NotTo(HaveOccurred())

				Expect(len(sqliteIDs)).To(Equal(len(flatfileIDs)))

				// Both should contain all test identifiers (ignoring path differences)
				for _, envelope := range testEnvelopes {
					found := false
					for _, id := range sqliteIDs {
						if id == envelope.Identifier {
							found = true
							break
						}
					}
					Expect(found).To(BeTrue(), "SQLite should contain %s", envelope.Identifier)
				}
			})

			It("should return identical records for Read operations", func() {
				for _, original := range testEnvelopes {
					sqliteRecord, err := sqliteBackend.Read(ctx, original.Identifier)
					Expect(err).NotTo(HaveOccurred())
					Expect(sqliteRecord.Identifier).To(Equal(original.Identifier))
					Expect(sqliteRecord.Schema).To(Equal(original.Schema))

					flatfileRecord, err := flatfileBackend.Read(ctx, original.Identifier)
					Expect(err).NotTo(HaveOccurred())
					Expect(flatfileRecord.Identifier).To(Equal(original.Identifier))
					Expect(flatfileRecord.Schema).To(Equal(original.Schema))

					// Both should match original
					Expect(sqliteRecord.Identifier).To(Equal(flatfileRecord.Identifier))
					Expect(sqliteRecord.Schema).To(Equal(flatfileRecord.Schema))
				}
			})

			It("should handle missing records identically", func() {
				nonExistentID := "CVE-9999-9999"

				sqliteRecord, sqliteErr := sqliteBackend.Read(ctx, nonExistentID)
				flatfileRecord, flatfileErr := flatfileBackend.Read(ctx, nonExistentID)

				Expect(sqliteErr).To(HaveOccurred())
				Expect(flatfileErr).To(HaveOccurred())
				Expect(sqliteRecord).To(BeNil())
				Expect(flatfileRecord).To(BeNil())
			})
		})

		Context("edge case handling", func() {
			It("should handle empty database identically", func() {
				// Create fresh backends
				emptySQLite, err := storage.NewSQLiteBackend(
					filepath.Join(tempDir, "empty.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())
				defer emptySQLite.Close(ctx)

				emptyFlatfile, err := storage.NewFlatFileBackend(
					filepath.Join(tempDir, "empty"),
				)
				Expect(err).NotTo(HaveOccurred())
				defer emptyFlatfile.Close(ctx)

				// Both should return empty lists
				sqliteIDs, err := emptySQLite.List(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(sqliteIDs).To(BeEmpty())

				flatfileIDs, err := emptyFlatfile.List(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(flatfileIDs).To(BeEmpty())

				// Both should return zero count
				sqliteCount, err := emptySQLite.Count(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(sqliteCount).To(Equal(0))

				flatfileCount, err := emptyFlatfile.Count(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(flatfileCount).To(Equal(0))
			})

			It("should handle large payloads identically", func() {
				largeItem := make(map[string]interface{})
				for i := 0; i < 100; i++ {
					largeItem[fmt.Sprintf("field_%d", i)] = fmt.Sprintf("value_%d", i)
				}

				largeEnvelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-LARGE-PAYLOAD",
					Item:       largeItem,
				}

				// Write to both
				err := sqliteBackend.Write(ctx, largeEnvelope)
				Expect(err).NotTo(HaveOccurred())

				err = flatfileBackend.Write(ctx, largeEnvelope)
				Expect(err).NotTo(HaveOccurred())

				// Close SQLite to persist
				err = sqliteBackend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				sqliteBackend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())

				// Read from both and verify
				sqliteRecord, err := sqliteBackend.Read(ctx, "CVE-LARGE-PAYLOAD")
				Expect(err).NotTo(HaveOccurred())

				flatfileRecord, err := flatfileBackend.Read(ctx, "CVE-LARGE-PAYLOAD")
				Expect(err).NotTo(HaveOccurred())

				// Both should have 100 fields
				sqliteItem := sqliteRecord.Item.(map[string]interface{})
				flatfileItem := flatfileRecord.Item.(map[string]interface{})

				Expect(len(sqliteItem)).To(Equal(100))
				Expect(len(flatfileItem)).To(Equal(100))
			})

			It("should handle special characters in identifiers", func() {
				specialEnvelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE:2023:SPECIAL-CHARS_123",
					Item:       map[string]interface{}{"test": "special"},
				}

				err := sqliteBackend.Write(ctx, specialEnvelope)
				Expect(err).NotTo(HaveOccurred())

				err = flatfileBackend.Write(ctx, specialEnvelope)
				Expect(err).NotTo(HaveOccurred())

				// Close and reopen SQLite
				err = sqliteBackend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				sqliteBackend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())

				// Both should be able to read the record
				sqliteRecord, err := sqliteBackend.Read(ctx, "CVE:2023:SPECIAL-CHARS_123")
				Expect(err).NotTo(HaveOccurred())
				Expect(sqliteRecord).NotTo(BeNil())

				flatfileRecord, err := flatfileBackend.Read(ctx, "CVE:2023:SPECIAL-CHARS_123")
				Expect(err).NotTo(HaveOccurred())
				Expect(flatfileRecord).NotTo(BeNil())
			})
		})

		Context("performance characteristics", func() {
			It("should handle batch writes efficiently", func() {
				// Create fresh backends with small batch size
				batchSQLite, err := storage.NewSQLiteBackend(
					filepath.Join(tempDir, "batch.db"),
					50,
				)
				Expect(err).NotTo(HaveOccurred())
				defer batchSQLite.Close(ctx)

				batchFlatfile, err := storage.NewFlatFileBackend(
					filepath.Join(tempDir, "batch"),
				)
				Expect(err).NotTo(HaveOccurred())
				defer batchFlatfile.Close(ctx)

				// Write 100 records to both
				for i := 0; i < 100; i++ {
					envelope := &storage.Envelope{
						Schema:     "https://example.com/schema/v1",
						Identifier: fmt.Sprintf("CVE-BATCH-%04d", i),
						Item:       map[string]interface{}{"id": i},
					}

					err = batchSQLite.Write(ctx, envelope)
					Expect(err).NotTo(HaveOccurred())

					err = batchFlatfile.Write(ctx, envelope)
					Expect(err).NotTo(HaveOccurred())
				}

				// Close SQLite to flush
				err = batchSQLite.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Reopen and verify counts match
				batchSQLite, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "batch.db"),
					50,
				)
				Expect(err).NotTo(HaveOccurred())

				sqliteCount, err := batchSQLite.Count(ctx)
				Expect(err).NotTo(HaveOccurred())

				flatfileCount, err := batchFlatfile.Count(ctx)
				Expect(err).NotTo(HaveOccurred())

				Expect(sqliteCount).To(Equal(flatfileCount))
				Expect(sqliteCount).To(Equal(100))
			})
		})
	})

	Describe("UnsupportedBackendError", func() {
		It("should implement error interface", func() {
			err := &storage.UnsupportedBackendError{Type: "test"}
			Expect(err.Error()).To(ContainSubstring("unsupported backend type"))
			Expect(err.Error()).To(ContainSubstring("test"))
		})

		It("should be type-assertable", func() {
			config := storage.Config{
				Type: "unknown",
				Path: tempDir,
			}

			_, err := storage.New(config)
			Expect(err).To(HaveOccurred())

			var unsupportedErr *storage.UnsupportedBackendError
			Expect(err).To(BeAssignableToTypeOf(unsupportedErr))
		})
	})
})
