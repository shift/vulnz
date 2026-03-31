package oval_test

import (
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/utils/oval"
)

var _ = Describe("OVAL Parser", func() {
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

	Describe("Parser Creation", func() {
		Context("when creating a new parser", func() {
			It("should create a parser successfully", func() {
				Expect(parser).NotTo(BeNil())
			})

			It("should have empty definitions initially", func() {
				defs := parser.GetDefinitions()
				Expect(defs).To(BeEmpty())
			})
		})
	})

	Describe("Parsing Files", func() {
		Context("when parsing a valid OVAL XML file", func() {
			It("should parse RHEL OVAL file successfully", func() {
				path := filepath.Join(testdataDir, "rhel-oval.xml")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				defs := parser.GetDefinitions()
				Expect(defs).To(HaveLen(3))
			})

			It("should parse Ubuntu OVAL file successfully", func() {
				path := filepath.Join(testdataDir, "ubuntu-oval.xml")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				defs := parser.GetDefinitions()
				Expect(defs).To(HaveLen(2))
			})

			It("should parse Debian OVAL file successfully", func() {
				path := filepath.Join(testdataDir, "debian-oval.xml")
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				defs := parser.GetDefinitions()
				Expect(defs).To(HaveLen(1))
			})
		})

		Context("when parsing malformed XML", func() {
			It("should return an error for malformed XML", func() {
				path := filepath.Join(testdataDir, "malformed.xml")
				err := parser.ParseFile(ctx, path)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when handling missing files", func() {
			It("should return an error for non-existent file", func() {
				err := parser.ParseFile(ctx, "nonexistent.xml")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to open file"))
			})
		})

		Context("when using cancelled context", func() {
			It("should return context error", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()

				err := parser.ParseFile(cancelledCtx, "test.xml")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("context"))
			})
		})
	})

	Describe("Parsing Bytes", func() {
		Context("when parsing OVAL from bytes", func() {
			It("should parse valid OVAL XML bytes", func() {
				path := filepath.Join(testdataDir, "rhel-oval.xml")
				data, err := os.ReadFile(path)
				Expect(err).NotTo(HaveOccurred())

				err = parser.ParseBytes(ctx, data)
				Expect(err).NotTo(HaveOccurred())

				defs := parser.GetDefinitions()
				Expect(defs).To(HaveLen(3))
			})
		})

		Context("when handling empty input", func() {
			It("should return error for empty byte slice", func() {
				err := parser.ParseBytes(ctx, []byte{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("empty input"))
			})
		})

		Context("when using cancelled context", func() {
			It("should return context error", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()

				err := parser.ParseBytes(cancelledCtx, []byte("test"))
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("context"))
			})
		})
	})

	Describe("Definition Retrieval", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when getting definition by ID", func() {
			It("should retrieve existing definition", func() {
				def, ok := parser.GetDefinition("oval:com.redhat.rhsa:def:20230001")
				Expect(ok).To(BeTrue())
				Expect(def).NotTo(BeNil())
				Expect(def.ID).To(Equal("oval:com.redhat.rhsa:def:20230001"))
			})

			It("should return false for non-existent ID", func() {
				def, ok := parser.GetDefinition("oval:com.redhat.rhsa:def:99999999")
				Expect(ok).To(BeFalse())
				Expect(def).To(BeNil())
			})
		})

		Context("when getting all definitions", func() {
			It("should return all parsed definitions", func() {
				defs := parser.GetDefinitions()
				Expect(defs).To(HaveLen(3))

				// Verify IDs
				ids := make([]string, len(defs))
				for i, def := range defs {
					ids[i] = def.ID
				}
				Expect(ids).To(ContainElements(
					"oval:com.redhat.rhsa:def:20230001",
					"oval:com.redhat.rhsa:def:20230002",
					"oval:com.redhat.rhsa:def:20230003",
				))
			})
		})
	})

	Describe("Filtering", func() {
		BeforeEach(func() {
			path := filepath.Join(testdataDir, "rhel-oval.xml")
			err := parser.ParseFile(ctx, path)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when filtering by severity", func() {
			It("should filter Critical severity definitions", func() {
				critical := parser.FilterBySeverity("Critical")
				Expect(critical).To(HaveLen(1))
				Expect(critical[0].ID).To(Equal("oval:com.redhat.rhsa:def:20230002"))
			})

			It("should filter Important severity definitions", func() {
				important := parser.FilterBySeverity("Important")
				Expect(important).To(HaveLen(1))
				Expect(important[0].ID).To(Equal("oval:com.redhat.rhsa:def:20230001"))
			})

			It("should filter Low severity definitions", func() {
				low := parser.FilterBySeverity("Low")
				Expect(low).To(HaveLen(1))
				Expect(low[0].ID).To(Equal("oval:com.redhat.rhsa:def:20230003"))
			})

			It("should be case-insensitive", func() {
				critical := parser.FilterBySeverity("critical")
				Expect(critical).To(HaveLen(1))
			})

			It("should return empty for non-matching severity", func() {
				medium := parser.FilterBySeverity("Medium")
				Expect(medium).To(BeEmpty())
			})
		})

		Context("when filtering by OS family", func() {
			It("should filter unix family definitions", func() {
				unix := parser.FilterByFamily("unix")
				Expect(unix).To(HaveLen(3))
			})

			It("should be case-insensitive", func() {
				unix := parser.FilterByFamily("UNIX")
				Expect(unix).To(HaveLen(3))
			})

			It("should return empty for non-matching family", func() {
				windows := parser.FilterByFamily("windows")
				Expect(windows).To(BeEmpty())
			})
		})

		Context("when combining multiple filters", func() {
			It("should filter by severity then by family", func() {
				critical := parser.FilterBySeverity("Critical")
				Expect(critical).To(HaveLen(1))

				// Verify it's unix family
				family := oval.GetFamily(critical[0])
				Expect(family).To(Equal("unix"))
			})
		})
	})

	Describe("Multi-file Parsing", func() {
		Context("when parsing multiple files", func() {
			It("should accumulate definitions from multiple files", func() {
				// Parse RHEL
				path1 := filepath.Join(testdataDir, "rhel-oval.xml")
				err := parser.ParseFile(ctx, path1)
				Expect(err).NotTo(HaveOccurred())

				// Parse Ubuntu
				path2 := filepath.Join(testdataDir, "ubuntu-oval.xml")
				err = parser.ParseFile(ctx, path2)
				Expect(err).NotTo(HaveOccurred())

				// Should have definitions from both files
				defs := parser.GetDefinitions()
				Expect(defs).To(HaveLen(5)) // 3 from RHEL + 2 from Ubuntu
			})
		})
	})

	Describe("Edge Cases", func() {
		Context("when dealing with duplicate IDs", func() {
			It("should overwrite duplicate definitions", func() {
				path := filepath.Join(testdataDir, "rhel-oval.xml")

				// Parse same file twice
				err := parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				err = parser.ParseFile(ctx, path)
				Expect(err).NotTo(HaveOccurred())

				// Should still have only 3 definitions (duplicates overwritten)
				defs := parser.GetDefinitions()
				Expect(defs).To(HaveLen(3))
			})
		})
	})
})
