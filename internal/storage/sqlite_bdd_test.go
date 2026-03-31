package storage_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/storage"
)

var _ = Describe("SQLite Backend", func() {
	var (
		backend storage.Backend
		tempDir string
		ctx     context.Context
	)

	BeforeEach(func() {
		tempDir = GinkgoT().TempDir()
		ctx = context.Background()
	})

	AfterEach(func() {
		if backend != nil {
			backend.Close(ctx)
		}
	})

	Describe("Backend initialization", func() {
		Context("when creating a new backend", func() {
			It("should create database successfully", func() {
				var err error
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(backend).NotTo(BeNil())
			})

			It("should create parent directories if they don't exist", func() {
				nestedPath := filepath.Join(tempDir, "nested", "dir", "test.db")
				var err error
				backend, err = storage.NewSQLiteBackend(nestedPath, 100)
				Expect(err).NotTo(HaveOccurred())
				Expect(backend).NotTo(BeNil())
			})

			It("should accept custom batch size", func() {
				var err error
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					50,
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(backend).NotTo(BeNil())
			})
		})
	})

	Describe("Write operations", func() {
		BeforeEach(func() {
			var err error
			backend, err = storage.NewSQLiteBackend(
				filepath.Join(tempDir, "test.db"),
				100,
			)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when writing a single envelope", func() {
			It("should write successfully", func() {
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-1234",
					Item: map[string]interface{}{
						"severity":    "HIGH",
						"description": "Test vulnerability",
					},
				}

				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should handle complex item structures", func() {
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-5678",
					Item: map[string]interface{}{
						"severity": "CRITICAL",
						"cvss": map[string]interface{}{
							"score":  9.8,
							"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						},
						"references": []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2023-5678",
							"https://github.com/advisories/CVE-2023-5678",
						},
					},
				}

				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when writing duplicate identifiers", func() {
			It("should update the existing record", func() {
				envelope1 := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-9999",
					Item: map[string]interface{}{
						"severity": "LOW",
					},
				}

				err := backend.Write(ctx, envelope1)
				Expect(err).NotTo(HaveOccurred())

				// Close to flush batch
				err = backend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Reopen backend
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())

				// Read the record
				retrieved, err := backend.Read(ctx, "CVE-2023-9999")
				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Item.(map[string]interface{})["severity"]).To(Equal("LOW"))

				// Write updated record
				envelope2 := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-9999",
					Item: map[string]interface{}{
						"severity": "CRITICAL",
					},
				}

				err = backend.Write(ctx, envelope2)
				Expect(err).NotTo(HaveOccurred())

				// Close to flush
				err = backend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Reopen and verify update
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())

				retrieved, err = backend.Read(ctx, "CVE-2023-9999")
				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Item.(map[string]interface{})["severity"]).To(Equal("CRITICAL"))
			})
		})

		Context("when context is cancelled", func() {
			It("should return context error on write", func() {
				cancelCtx, cancel := context.WithCancel(ctx)
				cancel() // Cancel immediately

				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-1111",
					Item:       map[string]interface{}{"test": "data"},
				}

				// Write small batch first
				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())

				// Try to flush with cancelled context
				err = backend.Close(cancelCtx)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("context canceled"))
			})
		})

		Context("when backend is closed", func() {
			It("should return error on write attempt", func() {
				err := backend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-2222",
					Item:       map[string]interface{}{"test": "data"},
				}

				err = backend.Write(ctx, envelope)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("closed"))
			})
		})
	})

	Describe("Batch operations", func() {
		Context("with batch size of 100", func() {
			BeforeEach(func() {
				var err error
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should flush batch on close", func() {
				// Write 50 records (less than batch size)
				for i := 0; i < 50; i++ {
					envelope := &storage.Envelope{
						Schema:     "https://example.com/schema/v1",
						Identifier: fmt.Sprintf("CVE-2023-%04d", i),
						Item: map[string]interface{}{
							"id": i,
						},
					}
					err := backend.Write(ctx, envelope)
					Expect(err).NotTo(HaveOccurred())
				}

				// Close to flush
				err := backend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Reopen and verify all 50 records
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())

				count, err := backend.Count(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(50))
			})

			It("should auto-flush when batch size reached", func() {
				// Write 101 records (batch size = 100)
				for i := 0; i < 101; i++ {
					envelope := &storage.Envelope{
						Schema:     "https://example.com/schema/v1",
						Identifier: fmt.Sprintf("CVE-2023-%04d", i),
						Item: map[string]interface{}{
							"id": i,
						},
					}
					err := backend.Write(ctx, envelope)
					Expect(err).NotTo(HaveOccurred())
				}

				// Close to flush remaining
				err := backend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Reopen and verify all 101 records
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())

				count, err := backend.Count(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(101))
			})

			It("should handle multiple auto-flushes", func() {
				// Write 250 records (2.5 batches)
				for i := 0; i < 250; i++ {
					envelope := &storage.Envelope{
						Schema:     "https://example.com/schema/v1",
						Identifier: fmt.Sprintf("CVE-2023-%04d", i),
						Item: map[string]interface{}{
							"id": i,
						},
					}
					err := backend.Write(ctx, envelope)
					Expect(err).NotTo(HaveOccurred())
				}

				err := backend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Reopen and verify all records
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())

				count, err := backend.Count(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(250))
			})
		})

		Context("with small batch size", func() {
			BeforeEach(func() {
				var err error
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					10, // Small batch for testing
				)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should flush multiple times automatically", func() {
				// Write 25 records (2.5 batches of 10)
				for i := 0; i < 25; i++ {
					envelope := &storage.Envelope{
						Schema:     "https://example.com/schema/v1",
						Identifier: fmt.Sprintf("CVE-2023-%04d", i),
						Item: map[string]interface{}{
							"id": i,
						},
					}
					err := backend.Write(ctx, envelope)
					Expect(err).NotTo(HaveOccurred())
				}

				err := backend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Reopen and verify
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					10,
				)
				Expect(err).NotTo(HaveOccurred())

				count, err := backend.Count(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(25))
			})
		})
	})

	Describe("Read operations", func() {
		BeforeEach(func() {
			var err error
			backend, err = storage.NewSQLiteBackend(
				filepath.Join(tempDir, "test.db"),
				100,
			)
			Expect(err).NotTo(HaveOccurred())

			// Seed with test data
			testData := []storage.Envelope{
				{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-1000",
					Item: map[string]interface{}{
						"severity":    "HIGH",
						"description": "Test vulnerability 1000",
					},
				},
				{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-2000",
					Item: map[string]interface{}{
						"severity":    "MEDIUM",
						"description": "Test vulnerability 2000",
					},
				},
			}

			for _, envelope := range testData {
				err := backend.Write(ctx, &envelope)
				Expect(err).NotTo(HaveOccurred())
			}

			// Flush to database
			err = backend.Close(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Reopen for reading
			backend, err = storage.NewSQLiteBackend(
				filepath.Join(tempDir, "test.db"),
				100,
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should read an existing record", func() {
			envelope, err := backend.Read(ctx, "CVE-2023-1000")
			Expect(err).NotTo(HaveOccurred())
			Expect(envelope).NotTo(BeNil())
			Expect(envelope.Identifier).To(Equal("CVE-2023-1000"))
			Expect(envelope.Schema).To(Equal("https://example.com/schema/v1"))

			item, ok := envelope.Item.(map[string]interface{})
			Expect(ok).To(BeTrue())
			Expect(item["severity"]).To(Equal("HIGH"))
			Expect(item["description"]).To(Equal("Test vulnerability 1000"))
		})

		It("should return error for non-existent record", func() {
			envelope, err := backend.Read(ctx, "CVE-9999-9999")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
			Expect(envelope).To(BeNil())
		})

		It("should preserve JSON structure", func() {
			envelope, err := backend.Read(ctx, "CVE-2023-2000")
			Expect(err).NotTo(HaveOccurred())

			// Marshal and unmarshal to verify structure
			data, err := json.Marshal(envelope)
			Expect(err).NotTo(HaveOccurred())

			var decoded storage.Envelope
			err = json.Unmarshal(data, &decoded)
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded.Identifier).To(Equal("CVE-2023-2000"))
		})

		Context("when context is cancelled", func() {
			It("should return context error", func() {
				cancelCtx, cancel := context.WithCancel(ctx)
				cancel()

				envelope, err := backend.Read(cancelCtx, "CVE-2023-1000")
				Expect(err).To(HaveOccurred())
				Expect(envelope).To(BeNil())
			})
		})
	})

	Describe("List operations", func() {
		BeforeEach(func() {
			var err error
			backend, err = storage.NewSQLiteBackend(
				filepath.Join(tempDir, "test.db"),
				100,
			)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("with populated database", func() {
			BeforeEach(func() {
				// Add 10 test records
				for i := 0; i < 10; i++ {
					envelope := &storage.Envelope{
						Schema:     "https://example.com/schema/v1",
						Identifier: fmt.Sprintf("CVE-2023-%04d", i),
						Item: map[string]interface{}{
							"id": i,
						},
					}
					err := backend.Write(ctx, envelope)
					Expect(err).NotTo(HaveOccurred())
				}

				err := backend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Reopen
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return all identifiers", func() {
				ids, err := backend.List(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(ids).To(HaveLen(10))
				Expect(ids).To(ContainElement("CVE-2023-0000"))
				Expect(ids).To(ContainElement("CVE-2023-0009"))
			})

			It("should return correct count", func() {
				count, err := backend.Count(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(10))
			})
		})

		Context("with empty database", func() {
			It("should return empty list", func() {
				err := backend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())

				ids, err := backend.List(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(ids).To(BeEmpty())
			})

			It("should return zero count", func() {
				count, err := backend.Count(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(0))
			})
		})

		Context("with large dataset", func() {
			It("should handle 1000+ records efficiently", func() {
				// Write 1000 records
				for i := 0; i < 1000; i++ {
					envelope := &storage.Envelope{
						Schema:     "https://example.com/schema/v1",
						Identifier: fmt.Sprintf("CVE-2023-%05d", i),
						Item: map[string]interface{}{
							"id": i,
						},
					}
					err := backend.Write(ctx, envelope)
					Expect(err).NotTo(HaveOccurred())
				}

				err := backend.Close(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Reopen
				backend, err = storage.NewSQLiteBackend(
					filepath.Join(tempDir, "test.db"),
					100,
				)
				Expect(err).NotTo(HaveOccurred())

				ids, err := backend.List(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(ids).To(HaveLen(1000))

				count, err := backend.Count(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(1000))
			})
		})
	})

	Describe("Close operations", func() {
		BeforeEach(func() {
			var err error
			backend, err = storage.NewSQLiteBackend(
				filepath.Join(tempDir, "test.db"),
				100,
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should flush pending batch", func() {
			// Write records
			for i := 0; i < 10; i++ {
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: fmt.Sprintf("CVE-2023-%04d", i),
					Item:       map[string]interface{}{"id": i},
				}
				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())
			}

			err := backend.Close(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Verify records were persisted
			backend, err = storage.NewSQLiteBackend(
				filepath.Join(tempDir, "test.db"),
				100,
			)
			Expect(err).NotTo(HaveOccurred())

			count, err := backend.Count(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(Equal(10))
		})

		It("should close database connection", func() {
			err := backend.Close(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Subsequent operations should fail
			envelope := &storage.Envelope{
				Schema:     "https://example.com/schema/v1",
				Identifier: "CVE-2023-9999",
				Item:       map[string]interface{}{"test": "data"},
			}
			err = backend.Write(ctx, envelope)
			Expect(err).To(HaveOccurred())
		})

		It("should be idempotent", func() {
			err := backend.Close(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Second close should not error
			err = backend.Close(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should move database to final location", func() {
			dbPath := filepath.Join(tempDir, "test.db")

			envelope := &storage.Envelope{
				Schema:     "https://example.com/schema/v1",
				Identifier: "CVE-2023-0001",
				Item:       map[string]interface{}{"test": "data"},
			}
			err := backend.Write(ctx, envelope)
			Expect(err).NotTo(HaveOccurred())

			err = backend.Close(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Final database should exist
			fileInfo, err := os.Stat(dbPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(fileInfo.Size()).To(BeNumerically(">", 0))
		})
	})
})
