package csaf_test

import (
	"context"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/utils/csaf"
)

var _ = Describe("CSAF Parser", func() {
	var (
		parser      *csaf.Parser
		ctx         context.Context
		testdataDir string
	)

	BeforeEach(func() {
		parser = csaf.NewParser()
		ctx = context.Background()
		testdataDir = "testdata"
	})

	Describe("Parser creation", func() {
		It("should create a new parser instance", func() {
			Expect(parser).NotTo(BeNil())
		})

		It("should have nil document initially", func() {
			Expect(parser.GetDocument()).To(BeNil())
		})
	})

	Describe("Parsing files", func() {
		Context("with valid CSAF JSON file", func() {
			It("should parse RHEL CSAF file successfully", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())
				Expect(parser.GetDocument()).NotTo(BeNil())
			})

			It("should parse SUSE CSAF file successfully", func() {
				path := filepath.Join(testdataDir, "suse-su-2023-0100.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())
				Expect(parser.GetDocument()).NotTo(BeNil())
			})

			It("should populate document fields correctly", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				Expect(doc.Document).NotTo(BeNil())
				Expect(doc.Document.Title).NotTo(BeNil())
				Expect(*doc.Document.Title).To(ContainSubstring("openssl"))
			})
		})

		Context("with malformed JSON", func() {
			It("should return error for malformed JSON", func() {
				path := filepath.Join(testdataDir, "malformed.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to parse"))
			})
		})

		Context("with missing file", func() {
			It("should return error for non-existent file", func() {
				path := filepath.Join(testdataDir, "nonexistent.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("does not exist"))
			})
		})

		Context("with cancelled context", func() {
			It("should respect context cancellation", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel() // Cancel immediately

				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(cancelCtx, path)
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(context.Canceled))
			})

			It("should respect context timeout", func() {
				timeoutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
				defer cancel()
				time.Sleep(10 * time.Millisecond) // Ensure timeout

				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(timeoutCtx, path)
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Parsing bytes", func() {
		Context("with valid CSAF JSON bytes", func() {
			It("should parse CSAF from bytes successfully", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				data, err := os.ReadFile(path)
				Expect(err).NotTo(HaveOccurred())

				err = parser.ParseBytes(ctx, data)
				Expect(err).NotTo(HaveOccurred())
				Expect(parser.GetDocument()).NotTo(BeNil())
			})

			It("should handle minimal valid CSAF", func() {
				minimalCSAF := []byte(`{
					"document": {
						"category": "csaf_security_advisory",
						"csaf_version": "2.0",
						"publisher": {
							"category": "vendor",
							"name": "Test",
							"namespace": "https://test.com"
						},
						"title": "Test Advisory",
						"tracking": {
							"id": "TEST-001",
							"status": "final",
							"version": "1",
							"initial_release_date": "2023-01-01T00:00:00Z",
							"current_release_date": "2023-01-01T00:00:00Z",
							"revision_history": []
						}
					}
				}`)

				err := parser.ParseBytes(ctx, minimalCSAF)
				Expect(err).NotTo(HaveOccurred())
				Expect(parser.GetDocument()).NotTo(BeNil())
			})
		})

		Context("with empty input", func() {
			It("should return error for empty bytes", func() {
				err := parser.ParseBytes(ctx, []byte{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("empty input"))
			})

			It("should return error for nil bytes", func() {
				err := parser.ParseBytes(ctx, nil)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("empty input"))
			})
		})

		Context("with invalid JSON", func() {
			It("should return error for malformed JSON bytes", func() {
				invalidJSON := []byte(`{"invalid": json`)
				err := parser.ParseBytes(ctx, invalidJSON)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to parse"))
			})
		})

		Context("with cancelled context", func() {
			It("should respect context cancellation", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				data := []byte(`{"document": {}}`)
				err := parser.ParseBytes(cancelCtx, data)
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(context.Canceled))
			})
		})
	})

	Describe("Validation", func() {
		Context("with valid CSAF document", func() {
			It("should validate RHEL CSAF successfully", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				err = parser.Validate()
				Expect(err).NotTo(HaveOccurred())
			})

			It("should validate SUSE CSAF successfully", func() {
				path := filepath.Join(testdataDir, "suse-su-2023-0100.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				err = parser.Validate()
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("with invalid CSAF document", func() {
			It("should reject document missing required fields", func() {
				path := filepath.Join(testdataDir, "invalid.json")
				err := parser.ParseFile(ctx, path)
				// The gocsaf library validates during parse, so we expect an error here
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("missing"))
			})
		})

		Context("without loaded document", func() {
			It("should return error when no document is loaded", func() {
				freshParser := csaf.NewParser()
				err := freshParser.Validate()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no document loaded"))
			})
		})
	})

	Describe("Document retrieval", func() {
		Context("after successful parse", func() {
			It("should return the parsed document", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				Expect(doc).NotTo(BeNil())
				Expect(doc.Document).NotTo(BeNil())
			})
		})

		Context("before parse", func() {
			It("should return nil for unparsed document", func() {
				freshParser := csaf.NewParser()
				Expect(freshParser.GetDocument()).To(BeNil())
			})
		})
	})
})
