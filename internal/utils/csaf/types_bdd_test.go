package csaf_test

import (
	"context"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/utils/csaf"
)

var _ = Describe("CSAF Types", func() {
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

	Describe("SimplifiedAdvisory", func() {
		Context("converting RHEL CSAF to simplified format", func() {
			It("should convert csaf.Advisory to simplified", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(simplified).NotTo(BeNil())
			})

			It("should preserve metadata", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(simplified.ID).To(Equal("RHSA-2023:0001"))
				Expect(simplified.Title).To(ContainSubstring("openssl"))
				Expect(simplified.Publisher).To(Equal("Red Hat"))
				Expect(simplified.Status).To(Equal("final"))
			})

			It("should extract summary from notes", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(simplified.Summary).NotTo(BeEmpty())
				Expect(simplified.Summary).To(ContainSubstring("openssl"))
			})

			It("should include aggregate severity", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(simplified.Severity).To(Equal("Important"))
			})

			It("should include release dates", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(simplified.InitialRelease).NotTo(BeEmpty())
				Expect(simplified.CurrentRelease).NotTo(BeEmpty())
				Expect(simplified.InitialRelease).To(ContainSubstring("2023"))
			})

			It("should aggregate CVEs", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(simplified.CVEs).NotTo(BeEmpty())
				Expect(simplified.CVEs).To(HaveLen(2))
				Expect(simplified.CVEs).To(ContainElements("CVE-2023-1234", "CVE-2023-5678"))
			})

			It("should aggregate products", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(simplified.Products).NotTo(BeEmpty())
				Expect(simplified.Products).To(ContainElement("openssl-1.1.1k-7.el8_6"))
			})
		})

		Context("converting SUSE CSAF to simplified format", func() {
			It("should handle SUSE advisory format", func() {
				path := filepath.Join(testdataDir, "suse-su-2023-0100.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(simplified).NotTo(BeNil())
				Expect(simplified.ID).To(Equal("SUSE-SU-2023:0100-1"))
				Expect(simplified.Publisher).To(Equal("SUSE"))
				Expect(simplified.Severity).To(Equal("important"))
			})

			It("should extract SUSE products", func() {
				path := filepath.Join(testdataDir, "suse-su-2023-0100.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(simplified.Products).To(ContainElement("kernel-default-5.14.21-150400.24.33.1"))
			})

			It("should extract SUSE CVEs", func() {
				path := filepath.Join(testdataDir, "suse-su-2023-0100.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(simplified.CVEs).To(ContainElement("CVE-2023-9999"))
			})
		})

		Context("with nil or invalid input", func() {
			It("should return nil for nil document", func() {
				simplified := csaf.Simplify(nil)
				Expect(simplified).To(BeNil())
			})

			It("should handle document with missing optional fields gracefully", func() {
				// Use minimal.json which has required fields but minimal optional ones
				path := filepath.Join(testdataDir, "minimal.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				// Should not panic, may have empty optional fields
				Expect(simplified).NotTo(BeNil())
				// But should have at least the required fields
				Expect(simplified.ID).To(Equal("TEST-001"))
			})
		})

		Context("field population", func() {
			It("should populate all available fields", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				// Verify all fields are populated
				Expect(simplified.ID).NotTo(BeEmpty())
				Expect(simplified.Title).NotTo(BeEmpty())
				Expect(simplified.Summary).NotTo(BeEmpty())
				Expect(simplified.Publisher).NotTo(BeEmpty())
				Expect(simplified.InitialRelease).NotTo(BeEmpty())
				Expect(simplified.CurrentRelease).NotTo(BeEmpty())
				Expect(simplified.CVEs).NotTo(BeEmpty())
				Expect(simplified.Products).NotTo(BeEmpty())
				Expect(simplified.Severity).NotTo(BeEmpty())
				Expect(simplified.Status).NotTo(BeEmpty())
			})

			It("should handle missing optional fields gracefully", func() {
				// Minimal document has required fields but not all optional ones
				path := filepath.Join(testdataDir, "minimal.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				// Should not panic on missing optional fields
				Expect(simplified).NotTo(BeNil())
				// Required fields should be present
				Expect(simplified.ID).To(Equal("TEST-001"))
				Expect(simplified.Status).To(Equal("draft"))
			})
		})

		Context("data integrity", func() {
			It("should maintain data consistency with original", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				// Verify extracted data matches original
				originalCVEs := csaf.ExtractCVEs(doc)
				Expect(simplified.CVEs).To(ConsistOf(originalCVEs))

				originalProducts := csaf.ExtractProducts(doc)
				Expect(simplified.Products).To(ConsistOf(originalProducts))
			})

			It("should preserve CVE count", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(len(simplified.CVEs)).To(Equal(2))
			})

			It("should preserve product count", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				simplified := csaf.Simplify(doc)

				Expect(len(simplified.Products)).To(BeNumerically(">=", 1))
			})
		})
	})
})
