package oval_test

import (
	"context"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/utils/oval"
	govalParser "github.com/quay/goval-parser/oval"
)

var _ = Describe("OVAL Types", func() {
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

	Describe("Simplification", func() {
		Context("when converting goval Definition to simplified format", func() {
			BeforeEach(func() {
				path := filepath.Join(testdataDir, "rhel-oval.xml")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should convert definition successfully", func() {
				def, ok := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				Expect(ok).To(BeTrue())

				simplified := oval.Simplify(def)
				Expect(simplified).NotTo(BeNil())
			})

			It("should preserve ID field", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				Expect(simplified.ID).To(Equal("oval:com.redhat.rhsa:def:20230001"))
			})

			It("should preserve title field", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				Expect(simplified.Title).To(ContainSubstring("openssl"))
			})

			It("should preserve description field", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				Expect(simplified.Description).NotTo(BeEmpty())
			})

			It("should extract severity field", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				Expect(simplified.Severity).To(Equal("Important"))
			})

			It("should extract family field", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				Expect(simplified.Family).To(Equal("unix"))
			})

			It("should extract references", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				Expect(simplified.References).NotTo(BeEmpty())
				Expect(len(simplified.References)).To(BeNumerically(">=", 1))
			})

			It("should extract criteria", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				Expect(simplified.Criteria).NotTo(BeNil())
				Expect(simplified.Criteria.Operator).NotTo(BeEmpty())
			})
		})

		Context("when handling missing fields gracefully", func() {
			It("should return nil for nil definition", func() {
				simplified := oval.Simplify(nil)
				Expect(simplified).To(BeNil())
			})

			It("should handle definition without advisory", func() {
				def := &govalParser.Definition{
					ID:    "test:def:001",
					Title: "Test Definition",
				}
				simplified := oval.Simplify(def)

				Expect(simplified).NotTo(BeNil())
				Expect(simplified.ID).To(Equal("test:def:001"))
				Expect(simplified.Severity).To(Equal("Unknown"))
			})

			It("should handle definition without references", func() {
				def := &govalParser.Definition{
					ID:         "test:def:001",
					Title:      "Test Definition",
					References: []govalParser.Reference{},
				}
				simplified := oval.Simplify(def)

				Expect(simplified).NotTo(BeNil())
				Expect(simplified.References).To(BeEmpty())
			})

			It("should handle definition without criteria", func() {
				def := &govalParser.Definition{
					ID:    "test:def:001",
					Title: "Test Definition",
				}
				simplified := oval.Simplify(def)

				Expect(simplified).NotTo(BeNil())
				Expect(simplified.Criteria).To(BeNil())
			})
		})
	})

	Describe("Reference Extraction", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when extracting references", func() {
			It("should extract CVE references", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				cveRefs := 0
				for _, ref := range simplified.References {
					if ref.Source == "CVE" {
						cveRefs++
					}
				}
				Expect(cveRefs).To(BeNumerically(">=", 1))
			})

			It("should extract RHSA references", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				hasRHSA := false
				for _, ref := range simplified.References {
					if ref.Source == "RHSA" {
						hasRHSA = true
						break
					}
				}
				Expect(hasRHSA).To(BeTrue())
			})
		})
	})

	Describe("Criteria Extraction", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when extracting criteria", func() {
			It("should extract operator", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				Expect(simplified.Criteria).NotTo(BeNil())
				Expect(simplified.Criteria.Operator).To(Equal("AND"))
			})

			It("should extract nested criteria", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				// Should have nested criteria
				if len(simplified.Criteria.Criteria) > 0 {
					nested := simplified.Criteria.Criteria[0]
					Expect(nested.Operator).NotTo(BeEmpty())
				}
			})

			It("should extract criterion", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				// Should have at least one criterion somewhere
				hasCriterion := false
				var checkCriteria func(*oval.Criteria)
				checkCriteria = func(c *oval.Criteria) {
					if c == nil {
						return
					}
					if len(c.Criterion) > 0 {
						hasCriterion = true
						return
					}
					for _, nested := range c.Criteria {
						checkCriteria(nested)
					}
				}
				checkCriteria(simplified.Criteria)

				Expect(hasCriterion).To(BeTrue())
			})
		})
	})

	Describe("ToMap Conversion", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when converting to map", func() {
			It("should create map with all fields", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)
				m := simplified.ToMap()

				Expect(m).To(HaveKey("id"))
				Expect(m).To(HaveKey("title"))
				Expect(m).To(HaveKey("description"))
				Expect(m).To(HaveKey("severity"))
				Expect(m).To(HaveKey("family"))
				Expect(m).To(HaveKey("references"))
			})

			It("should include criteria if present", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)
				m := simplified.ToMap()

				Expect(m).To(HaveKey("criteria"))
			})

			It("should format references as list of maps", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)
				m := simplified.ToMap()

				refs, ok := m["references"].([]map[string]string)
				Expect(ok).To(BeTrue())
				Expect(refs).NotTo(BeEmpty())
			})
		})
	})

	Describe("CVE Helper Methods", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when checking for CVE", func() {
			It("should find existing CVE", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				hasCVE := simplified.HasCVE("CVE-2023-1234")
				Expect(hasCVE).To(BeTrue())
			})

			It("should be case-insensitive", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				hasCVE := simplified.HasCVE("cve-2023-1234")
				Expect(hasCVE).To(BeTrue())
			})

			It("should return false for non-existent CVE", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				hasCVE := simplified.HasCVE("CVE-9999-9999")
				Expect(hasCVE).To(BeFalse())
			})
		})

		Context("when getting all CVEs", func() {
			It("should return all CVE IDs", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				cves := simplified.GetCVEs()
				Expect(cves).To(ContainElement("CVE-2023-1234"))
			})

			It("should return multiple CVEs", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				simplified := oval.Simplify(def)

				cves := simplified.GetCVEs()
				Expect(len(cves)).To(BeNumerically(">=", 2))
			})

			It("should return empty list if no CVEs", func() {
				def, _ := parser.GetDefinition("oval:com.redhat.rhsa:def:20230003")
				simplified := oval.Simplify(def)

				cves := simplified.GetCVEs()
				Expect(cves).To(BeEmpty())
			})
		})
	})
})
