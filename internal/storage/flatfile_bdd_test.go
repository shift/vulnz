package storage_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/storage"
)

var _ = Describe("Flat-File Backend", func() {
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
			It("should create root directory successfully", func() {
				rootDir := filepath.Join(tempDir, "results")
				var err error
				backend, err = storage.NewFlatFileBackend(rootDir)
				Expect(err).NotTo(HaveOccurred())
				Expect(backend).NotTo(BeNil())

				// Verify directory exists
				info, err := os.Stat(rootDir)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.IsDir()).To(BeTrue())
			})

			It("should handle nested directory creation", func() {
				rootDir := filepath.Join(tempDir, "deeply", "nested", "results")
				var err error
				backend, err = storage.NewFlatFileBackend(rootDir)
				Expect(err).NotTo(HaveOccurred())
				Expect(backend).NotTo(BeNil())

				info, err := os.Stat(rootDir)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.IsDir()).To(BeTrue())
			})

			It("should succeed if directory already exists", func() {
				rootDir := filepath.Join(tempDir, "results")
				err := os.MkdirAll(rootDir, 0755)
				Expect(err).NotTo(HaveOccurred())

				backend, err = storage.NewFlatFileBackend(rootDir)
				Expect(err).NotTo(HaveOccurred())
				Expect(backend).NotTo(BeNil())
			})
		})
	})

	Describe("Write operations", func() {
		BeforeEach(func() {
			var err error
			backend, err = storage.NewFlatFileBackend(filepath.Join(tempDir, "results"))
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when writing a single envelope", func() {
			It("should write JSON file with pretty-print", func() {
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

				// Verify file was created with pretty-print
				filePath := filepath.Join(tempDir, "results", "nvd", "CVE-2023-1234.json")
				data, err := os.ReadFile(filePath)
				Expect(err).NotTo(HaveOccurred())

				// Check for pretty-print indentation
				content := string(data)
				Expect(content).To(ContainSubstring("\n"))
				Expect(content).To(ContainSubstring("  ")) // 2-space indent
			})

			It("should create nested directories automatically", func() {
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "alpine:3.18:CVE-2023-5678",
					Item: map[string]interface{}{
						"package": "openssl",
						"version": "1.1.1",
					},
				}

				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())

				// Verify nested directory was created
				dirPath := filepath.Join(tempDir, "results", "alpine")
				info, err := os.Stat(dirPath)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.IsDir()).To(BeTrue())
			})

			It("should use atomic writes (temp + rename)", func() {
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-9999",
					Item: map[string]interface{}{
						"test": "atomic write",
					},
				}

				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())

				// Verify final file exists
				filePath := filepath.Join(tempDir, "results", "nvd", "CVE-2023-9999.json")
				_, err = os.Stat(filePath)
				Expect(err).NotTo(HaveOccurred())

				// Verify temp file was removed
				tempFilePath := filePath + ".tmp"
				_, err = os.Stat(tempFilePath)
				Expect(os.IsNotExist(err)).To(BeTrue())
			})

			It("should sanitize filenames", func() {
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE:2023:1234",
					Item: map[string]interface{}{
						"test": "sanitization",
					},
				}

				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())

				// Colons should be sanitized
				filePath := filepath.Join(tempDir, "results", "nvd", "CVE_2023_1234.json")
				_, err = os.Stat(filePath)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when handling different identifier formats", func() {
			It("should extract namespace from CVE IDs", func() {
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-1111",
					Item:       map[string]interface{}{"test": "nvd"},
				}

				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())

				filePath := filepath.Join(tempDir, "results", "nvd", "CVE-2023-1111.json")
				_, err = os.Stat(filePath)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should extract namespace from GHSA IDs", func() {
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "GHSA-xxxx-yyyy-zzzz",
					Item:       map[string]interface{}{"test": "github"},
				}

				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())

				filePath := filepath.Join(tempDir, "results", "github", "GHSA-xxxx-yyyy-zzzz.json")
				_, err = os.Stat(filePath)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should extract namespace from colon-separated format", func() {
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "alpine:3.18:CVE-2023-2222",
					Item:       map[string]interface{}{"test": "alpine"},
				}

				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())

				filePath := filepath.Join(tempDir, "results", "alpine", "alpine_3.18_CVE-2023-2222.json")
				_, err = os.Stat(filePath)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should extract namespace from slash-separated format", func() {
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "ubuntu/focal/CVE-2023-3333",
					Item:       map[string]interface{}{"test": "ubuntu"},
				}

				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())

				// Should create nested directory structure
				filePath := filepath.Join(tempDir, "results", "ubuntu", "focal", "CVE-2023-3333.json")
				_, err = os.Stat(filePath)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should use unknown namespace for unrecognized format", func() {
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CUSTOM-2023-4444",
					Item:       map[string]interface{}{"test": "unknown"},
				}

				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())

				filePath := filepath.Join(tempDir, "results", "unknown", "CUSTOM-2023-4444.json")
				_, err = os.Stat(filePath)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when updating existing files", func() {
			It("should overwrite existing file", func() {
				envelope1 := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-5555",
					Item: map[string]interface{}{
						"severity": "LOW",
					},
				}

				err := backend.Write(ctx, envelope1)
				Expect(err).NotTo(HaveOccurred())

				// Update with new content
				envelope2 := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "CVE-2023-5555",
					Item: map[string]interface{}{
						"severity": "CRITICAL",
					},
				}

				err = backend.Write(ctx, envelope2)
				Expect(err).NotTo(HaveOccurred())

				// Read and verify update
				retrieved, err := backend.Read(ctx, "CVE-2023-5555")
				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Item.(map[string]interface{})["severity"]).To(Equal("CRITICAL"))
			})
		})
	})

	Describe("Read operations", func() {
		BeforeEach(func() {
			var err error
			backend, err = storage.NewFlatFileBackend(filepath.Join(tempDir, "results"))
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
					Identifier: "alpine:3.18:CVE-2023-2000",
					Item: map[string]interface{}{
						"package": "openssl",
						"version": "1.1.1",
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
			}

			for _, envelope := range testData {
				err := backend.Write(ctx, &envelope)
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("should read an existing CVE file", func() {
			envelope, err := backend.Read(ctx, "CVE-2023-1000")
			Expect(err).NotTo(HaveOccurred())
			Expect(envelope).NotTo(BeNil())
			Expect(envelope.Identifier).To(Equal("CVE-2023-1000"))

			item, ok := envelope.Item.(map[string]interface{})
			Expect(ok).To(BeTrue())
			Expect(item["severity"]).To(Equal("HIGH"))
		})

		It("should read namespaced identifier", func() {
			envelope, err := backend.Read(ctx, "alpine:3.18:CVE-2023-2000")
			Expect(err).NotTo(HaveOccurred())
			Expect(envelope).NotTo(BeNil())
			Expect(envelope.Identifier).To(Equal("alpine:3.18:CVE-2023-2000"))
		})

		It("should read GHSA identifier", func() {
			envelope, err := backend.Read(ctx, "GHSA-abcd-efgh-ijkl")
			Expect(err).NotTo(HaveOccurred())
			Expect(envelope).NotTo(BeNil())
			Expect(envelope.Identifier).To(Equal("GHSA-abcd-efgh-ijkl"))
		})

		It("should return error for missing file", func() {
			envelope, err := backend.Read(ctx, "CVE-9999-9999")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
			Expect(envelope).To(BeNil())
		})

		Context("when handling corrupted JSON", func() {
			It("should return error for malformed JSON", func() {
				// Write corrupted JSON manually
				corruptedPath := filepath.Join(tempDir, "results", "nvd", "CVE-CORRUPT-0001.json")
				err := os.MkdirAll(filepath.Dir(corruptedPath), 0755)
				Expect(err).NotTo(HaveOccurred())

				err = os.WriteFile(corruptedPath, []byte("{ invalid json"), 0644)
				Expect(err).NotTo(HaveOccurred())

				envelope, err := backend.Read(ctx, "CVE-CORRUPT-0001")
				Expect(err).To(HaveOccurred())
				Expect(envelope).To(BeNil())
			})
		})

		It("should preserve complex JSON structures", func() {
			// Write complex structure
			complexEnvelope := &storage.Envelope{
				Schema:     "https://example.com/schema/v1",
				Identifier: "CVE-2023-COMPLEX",
				Item: map[string]interface{}{
					"severity": "CRITICAL",
					"cvss": map[string]interface{}{
						"score":  9.8,
						"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					},
					"references": []string{
						"https://nvd.nist.gov/vuln/detail/CVE-2023-COMPLEX",
						"https://github.com/advisories/CVE-2023-COMPLEX",
					},
					"affected": []map[string]interface{}{
						{
							"package":  "openssl",
							"versions": []string{"1.1.1a", "1.1.1b"},
						},
					},
				},
			}

			err := backend.Write(ctx, complexEnvelope)
			Expect(err).NotTo(HaveOccurred())

			// Read back and verify structure
			envelope, err := backend.Read(ctx, "CVE-2023-COMPLEX")
			Expect(err).NotTo(HaveOccurred())

			item := envelope.Item.(map[string]interface{})
			cvss := item["cvss"].(map[string]interface{})
			Expect(cvss["score"]).To(Equal(9.8))

			references := item["references"].([]interface{})
			Expect(references).To(HaveLen(2))
		})
	})

	Describe("List operations", func() {
		BeforeEach(func() {
			var err error
			backend, err = storage.NewFlatFileBackend(filepath.Join(tempDir, "results"))
			Expect(err).NotTo(HaveOccurred())
		})

		Context("with populated directory", func() {
			BeforeEach(func() {
				// Add records in different namespaces
				testData := []string{
					"CVE-2023-0001",
					"CVE-2023-0002",
					"CVE-2023-0003",
					"GHSA-aaaa-bbbb-cccc",
					"GHSA-dddd-eeee-ffff",
					"alpine:3.18:CVE-2023-0004",
					"alpine:3.18:CVE-2023-0005",
				}

				for _, id := range testData {
					envelope := &storage.Envelope{
						Schema:     "https://example.com/schema/v1",
						Identifier: id,
						Item:       map[string]interface{}{"id": id},
					}
					err := backend.Write(ctx, envelope)
					Expect(err).NotTo(HaveOccurred())
				}
			})

			It("should walk directory tree and return all IDs", func() {
				ids, err := backend.List(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(ids).To(HaveLen(7))
				Expect(ids).To(ContainElement(ContainSubstring("CVE-2023-0001")))
				Expect(ids).To(ContainElement(ContainSubstring("GHSA-aaaa-bbbb-cccc")))
			})

			It("should handle nested namespaces", func() {
				ids, err := backend.List(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Should include alpine namespaced entries
				alpineCount := 0
				for _, id := range ids {
					if id == "alpine/alpine_3.18_CVE-2023-0004" ||
						id == "alpine/alpine_3.18_CVE-2023-0005" {
						alpineCount++
					}
				}
				Expect(alpineCount).To(Equal(2))
			})

			It("should ignore non-JSON files", func() {
				// Create a non-JSON file
				txtPath := filepath.Join(tempDir, "results", "nvd", "README.txt")
				err := os.WriteFile(txtPath, []byte("test"), 0644)
				Expect(err).NotTo(HaveOccurred())

				ids, err := backend.List(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Should not include README.txt
				for _, id := range ids {
					Expect(id).NotTo(ContainSubstring("README"))
				}
			})

			It("should ignore .tmp files", func() {
				// Create a temp file
				tmpPath := filepath.Join(tempDir, "results", "nvd", "CVE-2023-TEMP.json.tmp")
				err := os.WriteFile(tmpPath, []byte("{}"), 0644)
				Expect(err).NotTo(HaveOccurred())

				ids, err := backend.List(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(ids).To(HaveLen(7)) // Should not include temp file
			})

			It("should return correct count", func() {
				count, err := backend.Count(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(7))
			})
		})

		Context("with empty directory", func() {
			It("should return empty list", func() {
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

		Context("with deeply nested structure", func() {
			It("should handle deep nesting", func() {
				// Create deeply nested identifier
				envelope := &storage.Envelope{
					Schema:     "https://example.com/schema/v1",
					Identifier: "os/linux/ubuntu/focal/CVE-2023-DEEP",
					Item:       map[string]interface{}{"test": "deep"},
				}

				err := backend.Write(ctx, envelope)
				Expect(err).NotTo(HaveOccurred())

				ids, err := backend.List(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(ids).To(HaveLen(1))
				Expect(ids[0]).To(ContainSubstring("focal"))
			})
		})
	})

	Describe("Close operations", func() {
		BeforeEach(func() {
			var err error
			backend, err = storage.NewFlatFileBackend(filepath.Join(tempDir, "results"))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should be a no-op for flat-file backend", func() {
			err := backend.Close(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should be idempotent", func() {
			err := backend.Close(ctx)
			Expect(err).NotTo(HaveOccurred())

			err = backend.Close(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allow operations after close", func() {
			err := backend.Close(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Should still be able to write
			envelope := &storage.Envelope{
				Schema:     "https://example.com/schema/v1",
				Identifier: "CVE-2023-AFTER-CLOSE",
				Item:       map[string]interface{}{"test": "data"},
			}

			err = backend.Write(ctx, envelope)
			Expect(err).NotTo(HaveOccurred())

			// Should still be able to read
			retrieved, err := backend.Read(ctx, "CVE-2023-AFTER-CLOSE")
			Expect(err).NotTo(HaveOccurred())
			Expect(retrieved).NotTo(BeNil())
		})
	})

	Describe("Namespace extraction", func() {
		BeforeEach(func() {
			var err error
			backend, err = storage.NewFlatFileBackend(filepath.Join(tempDir, "results"))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle Debian DSA identifiers", func() {
			envelope := &storage.Envelope{
				Schema:     "https://example.com/schema/v1",
				Identifier: "DSA-1234-1",
				Item:       map[string]interface{}{"distro": "debian"},
			}

			err := backend.Write(ctx, envelope)
			Expect(err).NotTo(HaveOccurred())

			filePath := filepath.Join(tempDir, "results", "debian", "DSA-1234-1.json")
			_, err = os.Stat(filePath)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle Red Hat RHSA identifiers", func() {
			envelope := &storage.Envelope{
				Schema:     "https://example.com/schema/v1",
				Identifier: "RHSA-2023:5678",
				Item:       map[string]interface{}{"distro": "redhat"},
			}

			err := backend.Write(ctx, envelope)
			Expect(err).NotTo(HaveOccurred())

			filePath := filepath.Join(tempDir, "results", "redhat", "RHSA-2023_5678.json")
			_, err = os.Stat(filePath)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("File integrity", func() {
		BeforeEach(func() {
			var err error
			backend, err = storage.NewFlatFileBackend(filepath.Join(tempDir, "results"))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should create valid JSON files", func() {
			envelope := &storage.Envelope{
				Schema:     "https://example.com/schema/v1",
				Identifier: "CVE-2023-VALID",
				Item: map[string]interface{}{
					"test": "validation",
				},
			}

			err := backend.Write(ctx, envelope)
			Expect(err).NotTo(HaveOccurred())

			// Read file directly and parse as JSON
			filePath := filepath.Join(tempDir, "results", "nvd", "CVE-2023-VALID.json")
			data, err := os.ReadFile(filePath)
			Expect(err).NotTo(HaveOccurred())

			var parsed storage.Envelope
			err = json.Unmarshal(data, &parsed)
			Expect(err).NotTo(HaveOccurred())
			Expect(parsed.Identifier).To(Equal("CVE-2023-VALID"))
		})

		It("should set correct file permissions", func() {
			envelope := &storage.Envelope{
				Schema:     "https://example.com/schema/v1",
				Identifier: "CVE-2023-PERMS",
				Item:       map[string]interface{}{"test": "permissions"},
			}

			err := backend.Write(ctx, envelope)
			Expect(err).NotTo(HaveOccurred())

			filePath := filepath.Join(tempDir, "results", "nvd", "CVE-2023-PERMS.json")
			info, err := os.Stat(filePath)
			Expect(err).NotTo(HaveOccurred())

			// Check file is readable
			Expect(info.Mode() & 0400).NotTo(BeZero())
		})
	})
})
