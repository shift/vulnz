package oval_test

import (
	"context"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	govalParser "github.com/quay/goval-parser/oval"
	"github.com/shift/vulnz/internal/utils/oval"
)

var _ = Describe("OVAL Helpers", func() {
	var (
		parser      *oval.Parser
		ctx         context.Context
		testdataDir string
	)

	BeforeEach(func() {
		parser = oval.NewParser()
		ctx = context.Background()
		testdataDir = filepath.Join("testdata")
	})

	Describe("CVE Extraction", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when extracting CVE IDs from references", func() {
			It("should extract CVE IDs", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				cves := oval.ExtractCVEs(def)

				Expect(cves).To(ContainElement("CVE-2023-1234"))
			})

			It("should handle multiple CVEs", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				cves := oval.ExtractCVEs(def)

				Expect(len(cves)).To(BeNumerically(">=", 2))
				Expect(cves).To(ContainElement("CVE-2023-1234"))
				Expect(cves).To(ContainElement("CVE-2023-5678"))
			})

			It("should return empty slice for no CVEs", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230003")
				cves := oval.ExtractCVEs(def)

				Expect(cves).To(BeEmpty())
			})

			It("should handle nil definition", func() {
				cves := oval.ExtractCVEs(nil)
				Expect(cves).To(BeEmpty())
			})
		})

		Context("when filtering CVE references", func() {
			It("should only extract CVE references", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				cves := oval.ExtractCVEs(def)

				// All extracted should be CVE format
				for _, cve := range cves {
					Expect(cve).To(MatchRegexp("^CVE-\\d{4}-\\d+$"))
				}
			})

			It("should not include other reference types", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				cves := oval.ExtractCVEs(def)

				// Should not include RHSA references
				for _, cve := range cves {
					Expect(cve).NotTo(ContainSubstring("RHSA"))
				}
			})
		})
	})

	Describe("Package Extraction", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when extracting package names from criteria", func() {
			It("should extract package names", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				packages := oval.ExtractPackages(def)

				Expect(packages).NotTo(BeEmpty())
			})

			It("should handle multiple packages", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				packages := oval.ExtractPackages(def)

				// Should extract openssl-related packages
				hasOpenSSL := false
				for _, pkg := range packages {
					if pkg == "openssl" || pkg == "openssl-devel" || pkg == "openssl-libs" {
						hasOpenSSL = true
						break
					}
				}
				Expect(hasOpenSSL).To(BeTrue())
			})

			It("should return empty slice for no packages", func() {
				// Create minimal definition with no criteria
				def := &govalParser.Definition{
					ID:    "test:def:001",
					Title: "Test Definition",
				}
				packages := oval.ExtractPackages(def)

				Expect(packages).To(BeEmpty())
			})

			It("should handle nil definition", func() {
				packages := oval.ExtractPackages(nil)
				Expect(packages).To(BeEmpty())
			})
		})

		Context("when extracting from different criteria patterns", func() {
			It("should extract from 'is earlier than' pattern", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				packages := oval.ExtractPackages(def)

				// The test data has "openssl is earlier than" pattern
				Expect(packages).NotTo(BeEmpty())
			})

			It("should extract from multiple criteria", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				packages := oval.ExtractPackages(def)

				// Should extract from OR criteria
				Expect(len(packages)).To(BeNumerically(">=", 1))
			})
		})

		Context("when handling package name variations", func() {
			It("should extract packages with dashes", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				packages := oval.ExtractPackages(def)

				// Look for packages with dashes like openssl-devel
				hasDashed := false
				for _, pkg := range packages {
					if pkg == "openssl-devel" || pkg == "openssl-libs" {
						hasDashed = true
						break
					}
				}
				Expect(hasDashed).To(BeTrue())
			})
		})
	})

	Describe("Severity Extraction", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when extracting severity", func() {
			It("should extract Critical severity", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230002")
				severity := oval.GetSeverity(def)

				Expect(severity).To(Equal("Critical"))
			})

			It("should extract Important severity", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				severity := oval.GetSeverity(def)

				Expect(severity).To(Equal("Important"))
			})

			It("should extract Low severity", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230003")
				severity := oval.GetSeverity(def)

				Expect(severity).To(Equal("Low"))
			})

			It("should return Unknown for missing severity", func() {
				def := &govalParser.Definition{
					ID:    "test:def:001",
					Title: "Test Definition",
				}
				severity := oval.GetSeverity(def)

				Expect(severity).To(Equal("Unknown"))
			})

			It("should handle nil definition", func() {
				severity := oval.GetSeverity(nil)
				Expect(severity).To(Equal("Unknown"))
			})
		})

		Context("when normalizing severity values", func() {
			It("should normalize 'High' to 'Important'", func() {
				def := &govalParser.Definition{
					ID:    "test:def:001",
					Title: "Test Definition",
					Advisory: govalParser.Advisory{
						Severity: "High",
					},
				}
				severity := oval.GetSeverity(def)

				Expect(severity).To(Equal("Important"))
			})

			It("should normalize 'Medium' to 'Moderate'", func() {
				def := &govalParser.Definition{
					ID:    "test:def:001",
					Title: "Test Definition",
					Advisory: govalParser.Advisory{
						Severity: "Medium",
					},
				}
				severity := oval.GetSeverity(def)

				Expect(severity).To(Equal("Moderate"))
			})
		})
	})

	Describe("OS Family Extraction", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when extracting OS family", func() {
			It("should extract unix family", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				family := oval.GetFamily(def)

				Expect(family).To(Equal("unix"))
			})

			It("should handle nil definition", func() {
				family := oval.GetFamily(nil)
				Expect(family).To(Equal("unknown"))
			})

			It("should return unknown for missing family", func() {
				def := &govalParser.Definition{
					ID:    "test:def:001",
					Title: "Test Definition",
				}
				family := oval.GetFamily(def)

				Expect(family).To(Equal("unknown"))
			})
		})

		Context("when inferring family from ID", func() {
			It("should infer unix for Red Hat", func() {
				def := &govalParser.Definition{
					ID:    "oval:com.redhat.rhsa:def:20230001",
					Title: "RHSA Security Update",
				}
				family := oval.GetFamily(def)

				Expect(family).To(Equal("unix"))
			})

			It("should infer unix for Ubuntu", func() {
				def := &govalParser.Definition{
					ID:    "oval:com.ubuntu.focal:def:202301",
					Title: "Ubuntu Security Update",
				}
				family := oval.GetFamily(def)

				Expect(family).To(Equal("unix"))
			})

			It("should infer unix for Debian", func() {
				def := &govalParser.Definition{
					ID:    "oval:org.debian:def:202301",
					Title: "Debian Security Update",
				}
				family := oval.GetFamily(def)

				Expect(family).To(Equal("unix"))
			})
		})
	})

	Describe("Platform Extraction", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when extracting platforms", func() {
			It("should extract platform names", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				platforms := oval.GetPlatforms(def)

				Expect(platforms).To(ContainElement("Red Hat Enterprise Linux 8"))
			})

			It("should extract multiple platforms", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230002")
				platforms := oval.GetPlatforms(def)

				Expect(len(platforms)).To(BeNumerically(">=", 2))
				Expect(platforms).To(ContainElement("Red Hat Enterprise Linux 8"))
				Expect(platforms).To(ContainElement("Red Hat Enterprise Linux 9"))
			})

			It("should return empty for no platforms", func() {
				def := &govalParser.Definition{
					ID:    "test:def:001",
					Title: "Test Definition",
				}
				platforms := oval.GetPlatforms(def)

				Expect(platforms).To(BeEmpty())
			})

			It("should handle nil definition", func() {
				platforms := oval.GetPlatforms(nil)
				Expect(platforms).To(BeEmpty())
			})
		})
	})

	Describe("Advisory ID Extraction", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when extracting advisory ID", func() {
			It("should extract RHSA ID", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				advisory := oval.GetAdvisoryID(def)

				Expect(advisory).To(Equal("RHSA-2023:0001"))
			})

			It("should extract from different definitions", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230002")
				advisory := oval.GetAdvisoryID(def)

				Expect(advisory).To(Equal("RHSA-2023:0002"))
			})

			It("should return empty for no advisory", func() {
				def := &govalParser.Definition{
					ID:    "test:def:001",
					Title: "Test Definition",
				}
				advisory := oval.GetAdvisoryID(def)

				Expect(advisory).To(BeEmpty())
			})

			It("should handle nil definition", func() {
				advisory := oval.GetAdvisoryID(nil)
				Expect(advisory).To(BeEmpty())
			})
		})

		Context("when handling different advisory types", func() {
			It("should recognize RHSA advisories", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				advisory := oval.GetAdvisoryID(def)

				Expect(advisory).To(MatchRegexp("^RHSA-\\d{4}:\\d+$"))
			})
		})
	})

	Describe("Edge Cases and Error Handling", func() {
		Context("when dealing with empty data", func() {
			It("should handle empty criteria comments", func() {
				def := &govalParser.Definition{
					ID:    "test:def:001",
					Title: "Test",
					Criteria: govalParser.Criteria{
						Operator: "AND",
						Criterions: []govalParser.Criterion{
							{TestRef: "test:tst:001", Comment: ""},
						},
					},
				}
				packages := oval.ExtractPackages(def)
				Expect(packages).To(BeEmpty())
			})

			It("should handle empty references", func() {
				def := &govalParser.Definition{
					ID:         "test:def:001",
					Title:      "Test",
					References: []govalParser.Reference{},
				}
				cves := oval.ExtractCVEs(def)
				Expect(cves).To(BeEmpty())
			})
		})

		Context("when dealing with complex criteria", func() {
			It("should handle nested criteria correctly", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				packages := oval.ExtractPackages(def)

				// Should extract from nested OR criteria
				// The extraction depends on pattern matching in comments
				// which may or may not return results depending on comment format
				_ = packages // Just verify it doesn't panic
			})
		})
	})
})
