package date_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/utils/date"
)

func TestDate(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Date Utils Suite")
}

var _ = Describe("NormalizeDate", func() {
	Context("when parsing RFC3339 format", func() {
		It("should parse RFC3339 with timezone", func() {
			result, err := date.NormalizeDate("2023-03-15T10:30:00Z")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse RFC3339 with offset timezone", func() {
			result, err := date.NormalizeDate("2023-03-15T10:30:00+05:30")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse RFC3339Nano format", func() {
			result, err := date.NormalizeDate("2023-03-15T10:30:00.123456789Z")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})
	})

	Context("when parsing RFC1123 format", func() {
		It("should parse RFC1123 date", func() {
			result, err := date.NormalizeDate("Mon, 15 Mar 2023 10:30:00 MST")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse RFC1123Z date", func() {
			result, err := date.NormalizeDate("Mon, 15 Mar 2023 10:30:00 +0000")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})
	})

	Context("when parsing ISO8601 format", func() {
		It("should parse standard ISO date", func() {
			result, err := date.NormalizeDate("2023-03-15")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse ISO date with time", func() {
			result, err := date.NormalizeDate("2023-03-15 10:30:00")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse ISO date with time (no seconds)", func() {
			result, err := date.NormalizeDate("2023-03-15 10:30")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})
	})

	Context("when parsing US date format", func() {
		It("should parse MM/DD/YYYY with time", func() {
			result, err := date.NormalizeDate("03/15/2023 10:30:00")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse MM/DD/YYYY", func() {
			result, err := date.NormalizeDate("03/15/2023")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse M/D/YYYY (single digit month and day)", func() {
			result, err := date.NormalizeDate("3/5/2023")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-05"))
		})
	})

	Context("when parsing Unix timestamps", func() {
		It("should parse Unix timestamp in seconds", func() {
			result, err := date.NormalizeDate("1678875000") // 2023-03-15 10:30:00 UTC
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse Unix timestamp zero", func() {
			_, err := date.NormalizeDate("0")
			Expect(err).To(HaveOccurred()) // Zero timestamp is out of valid range
		})

		It("should reject timestamps outside valid range", func() {
			_, err := date.NormalizeDate("9999999999") // Far future
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when parsing other common formats", func() {
		It("should parse DD-MMM-YYYY format", func() {
			result, err := date.NormalizeDate("15-Mar-2023")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse DD-MMM-YY format", func() {
			result, err := date.NormalizeDate("15-Mar-23")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse MMM DD, YYYY format", func() {
			result, err := date.NormalizeDate("Mar 15, 2023")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse MMMM DD, YYYY format", func() {
			result, err := date.NormalizeDate("March 15, 2023")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse date with forward slash separator", func() {
			result, err := date.NormalizeDate("2023/03/15")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})
	})

	Context("when handling edge cases", func() {
		It("should return error for empty string", func() {
			_, err := date.NormalizeDate("")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("empty"))
		})

		It("should return error for whitespace only", func() {
			_, err := date.NormalizeDate("   ")
			Expect(err).To(HaveOccurred())
		})

		It("should handle dates with leading/trailing whitespace", func() {
			result, err := date.NormalizeDate("  2023-03-15  ")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should return error for invalid date", func() {
			_, err := date.NormalizeDate("not-a-date")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unable to parse"))
		})

		It("should return error for malformed date", func() {
			_, err := date.NormalizeDate("2023-13-45")
			Expect(err).To(HaveOccurred())
		})

		It("should return error for partial date", func() {
			_, err := date.NormalizeDate("2023-03")
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when parsing real-world vulnerability data dates", func() {
		It("should parse NVD published date format", func() {
			result, err := date.NormalizeDate("2023-03-15T14:15:07.123Z")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse Debian Security Advisory date", func() {
			result, err := date.NormalizeDate("15 Mar 2023")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse Alpine secdb date format", func() {
			result, err := date.NormalizeDate("2023-03-15")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse Red Hat CVE date format", func() {
			result, err := date.NormalizeDate("2023-03-15T10:30:00Z")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse Ubuntu CVE tracker date", func() {
			result, err := date.NormalizeDate("2023-03-15 10:30:00 UTC")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse GitHub Advisory date format", func() {
			result, err := date.NormalizeDate("2023-03-15T10:30:00Z")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})

		It("should parse CVE JSON 5.0 date format", func() {
			result, err := date.NormalizeDate("2023-03-15T10:30:00.000Z")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2023-03-15"))
		})
	})

	Context("when parsing dates across different years", func() {
		It("should parse dates from 2000", func() {
			result, err := date.NormalizeDate("2000-01-01")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2000-01-01"))
		})

		It("should parse dates from 2025", func() {
			result, err := date.NormalizeDate("2025-12-31")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2025-12-31"))
		})

		It("should parse leap year date", func() {
			result, err := date.NormalizeDate("2024-02-29")
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal("2024-02-29"))
		})
	})

	Context("when testing all supported formats comprehensively", func() {
		DescribeTable("should correctly parse various date formats",
			func(input, expected string) {
				result, err := date.NormalizeDate(input)
				Expect(err).ToNot(HaveOccurred())
				Expect(result).To(Equal(expected))
			},
			Entry("RFC3339 UTC", "2023-06-15T14:30:00Z", "2023-06-15"),
			Entry("RFC3339 with offset", "2023-06-15T14:30:00+02:00", "2023-06-15"),
			Entry("ISO date only", "2023-06-15", "2023-06-15"),
			Entry("US format", "06/15/2023", "2023-06-15"),
			Entry("Unix timestamp", "1686838200", "2023-06-15"),
			Entry("Month name short", "Jun 15, 2023", "2023-06-15"),
			Entry("Month name full", "June 15, 2023", "2023-06-15"),
		)

		DescribeTable("should return errors for invalid inputs",
			func(input string) {
				_, err := date.NormalizeDate(input)
				Expect(err).To(HaveOccurred())
			},
			Entry("empty string", ""),
			Entry("random text", "invalid-date-string"),
			Entry("only numbers but invalid", "12345"),
			Entry("partial date", "2023-06"),
			Entry("invalid month", "2023-13-01"),
			Entry("invalid day", "2023-01-32"),
		)
	})
})
