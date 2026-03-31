package csaf_test

import (
	"context"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/utils/csaf"
)

var _ = Describe("CSAF Extractor", func() {
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

	Describe("CVE extraction", func() {
		Context("from RHEL advisory with multiple CVEs", func() {
			It("should extract CVE IDs from vulnerabilities", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				cves := csaf.ExtractCVEs(doc)

				Expect(cves).NotTo(BeEmpty())
				Expect(cves).To(HaveLen(2))
				Expect(cves).To(ContainElements("CVE-2023-1234", "CVE-2023-5678"))
			})

			It("should handle multiple CVEs", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				cves := csaf.ExtractCVEs(doc)

				Expect(len(cves)).To(BeNumerically(">=", 2))
			})

			It("should deduplicate CVEs", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				cves := csaf.ExtractCVEs(doc)

				// Check uniqueness
				uniqueMap := make(map[string]bool)
				for _, cve := range cves {
					Expect(uniqueMap[cve]).To(BeFalse(), "CVE %s should not be duplicated", cve)
					uniqueMap[cve] = true
				}
			})
		})

		Context("from SUSE advisory", func() {
			It("should extract CVE from SUSE advisory", func() {
				path := filepath.Join(testdataDir, "suse-su-2023-0100.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				cves := csaf.ExtractCVEs(doc)

				Expect(cves).NotTo(BeEmpty())
				Expect(cves).To(ContainElement("CVE-2023-9999"))
			})
		})

		Context("from document with no vulnerabilities", func() {
			It("should return empty slice for nil document", func() {
				cves := csaf.ExtractCVEs(nil)
				Expect(cves).To(BeEmpty())
			})

			It("should return empty slice for document without vulnerabilities", func() {
				path := filepath.Join(testdataDir, "minimal.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				cves := csaf.ExtractCVEs(doc)
				Expect(cves).To(BeEmpty())
			})
		})
	})

	Describe("Product extraction", func() {
		Context("from RHEL advisory", func() {
			It("should extract product names from tree", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				products := csaf.ExtractProducts(doc)

				Expect(products).NotTo(BeEmpty())
				Expect(products).To(ContainElement("openssl-1.1.1k-7.el8_6"))
			})

			It("should handle product relationships", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				products := csaf.ExtractProducts(doc)

				Expect(products).NotTo(BeEmpty())
			})
		})

		Context("from SUSE advisory", func() {
			It("should extract SUSE products", func() {
				path := filepath.Join(testdataDir, "suse-su-2023-0100.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				products := csaf.ExtractProducts(doc)

				Expect(products).NotTo(BeEmpty())
				Expect(products).To(ContainElement("kernel-default-5.14.21-150400.24.33.1"))
			})
		})

		Context("from nested product branches", func() {
			It("should recursively extract from nested branches", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				products := csaf.ExtractProducts(doc)

				// Should find products in nested structure
				Expect(products).NotTo(BeEmpty())
			})
		})

		Context("from document with no product tree", func() {
			It("should return empty slice for nil document", func() {
				products := csaf.ExtractProducts(nil)
				Expect(products).To(BeEmpty())
			})
		})
	})

	Describe("Remediation extraction", func() {
		Context("from RHEL advisory", func() {
			It("should extract all remediations", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				remediations := csaf.ExtractRemediations(doc)

				Expect(remediations).NotTo(BeEmpty())
				Expect(len(remediations)).To(BeNumerically(">=", 1))
			})

			It("should categorize by type", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				remediations := csaf.ExtractRemediations(doc)

				foundVendorFix := false
				for _, rem := range remediations {
					if rem.Category == "vendor_fix" {
						foundVendorFix = true
						Expect(rem.Details).NotTo(BeEmpty())
					}
				}
				Expect(foundVendorFix).To(BeTrue())
			})

			It("should include URLs", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				remediations := csaf.ExtractRemediations(doc)

				foundURL := false
				for _, rem := range remediations {
					if rem.URL != "" {
						foundURL = true
						Expect(rem.URL).To(ContainSubstring("https://"))
					}
				}
				Expect(foundURL).To(BeTrue())
			})

			It("should include product IDs", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				remediations := csaf.ExtractRemediations(doc)

				foundProductIDs := false
				for _, rem := range remediations {
					if len(rem.ProductIDs) > 0 {
						foundProductIDs = true
						Expect(rem.ProductIDs[0]).To(ContainSubstring("openssl"))
					}
				}
				Expect(foundProductIDs).To(BeTrue())
			})
		})

		Context("from SUSE advisory with workarounds", func() {
			It("should extract vendor fixes and workarounds", func() {
				path := filepath.Join(testdataDir, "suse-su-2023-0100.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				remediations := csaf.ExtractRemediations(doc)

				Expect(remediations).To(HaveLen(2))

				categories := make(map[string]bool)
				for _, rem := range remediations {
					categories[rem.Category] = true
				}
				Expect(categories).To(HaveKey("vendor_fix"))
				Expect(categories).To(HaveKey("workaround"))
			})
		})

		Context("from document with no remediations", func() {
			It("should return empty slice for nil document", func() {
				remediations := csaf.ExtractRemediations(nil)
				Expect(remediations).To(BeEmpty())
			})
		})
	})

	Describe("Score extraction", func() {
		Context("from RHEL advisory with CVSS v3", func() {
			It("should extract CVSS v3 scores", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				scores := csaf.ExtractScores(doc)

				Expect(scores).NotTo(BeEmpty())
			})

			It("should include base score and severity", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				scores := csaf.ExtractScores(doc)

				for _, score := range scores {
					Expect(score.BaseScore).To(BeNumerically(">", 0))
					Expect(score.Severity).NotTo(BeEmpty())
				}
			})

			It("should include vector strings", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				scores := csaf.ExtractScores(doc)

				for _, score := range scores {
					Expect(score.Vector).To(ContainSubstring("CVSS:3.1/"))
				}
			})

			It("should link scores to CVEs", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				scores := csaf.ExtractScores(doc)

				foundCVE := false
				for _, score := range scores {
					if score.CVE != "" {
						foundCVE = true
						Expect(score.CVE).To(ContainSubstring("CVE-"))
					}
				}
				Expect(foundCVE).To(BeTrue())
			})

			It("should include product IDs", func() {
				path := filepath.Join(testdataDir, "rhsa-2023-0001.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				scores := csaf.ExtractScores(doc)

				foundProducts := false
				for _, score := range scores {
					if len(score.ProductIDs) > 0 {
						foundProducts = true
					}
				}
				Expect(foundProducts).To(BeTrue())
			})
		})

		Context("from SUSE advisory with CVSS v2 and v3", func() {
			It("should extract both CVSS v2 and v3 scores", func() {
				path := filepath.Join(testdataDir, "suse-su-2023-0100.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				scores := csaf.ExtractScores(doc)

				Expect(scores).To(HaveLen(2))

				versions := make(map[string]bool)
				for _, score := range scores {
					versions[score.Version] = true
				}
				Expect(versions).To(HaveKey("3.1"))
				Expect(versions).To(HaveKey("2.0"))
			})

			It("should calculate CVSS v2 severity", func() {
				path := filepath.Join(testdataDir, "suse-su-2023-0100.json")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				doc := parser.GetDocument()
				scores := csaf.ExtractScores(doc)

				foundV2 := false
				for _, score := range scores {
					if score.Version == "2.0" {
						foundV2 = true
						// CVSS v2 base score of 7.2 should be HIGH
						Expect(score.Severity).To(Equal("HIGH"))
					}
				}
				Expect(foundV2).To(BeTrue())
			})
		})

		Context("from document with no scores", func() {
			It("should return empty slice for nil document", func() {
				scores := csaf.ExtractScores(nil)
				Expect(scores).To(BeEmpty())
			})
		})
	})
})
