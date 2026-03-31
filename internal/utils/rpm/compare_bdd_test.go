package rpm_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/utils/rpm"
)

var _ = Describe("RPM Version Comparison Algorithm", func() {
	Describe("Numeric comparison", func() {
		Context("when comparing basic numeric versions", func() {
			It("should compare 1.2.3 < 1.2.4", func() {
				v1, _ := rpm.Parse("1.2.3")
				v2, _ := rpm.Parse("1.2.4")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.10 > 1.9 (not string compare)", func() {
				v1, _ := rpm.Parse("1.10")
				v2, _ := rpm.Parse("1.9")
				Expect(v1.Compare(v2)).To(Equal(1))
			})

			It("should compare 1.100 > 1.99", func() {
				v1, _ := rpm.Parse("1.100")
				v2, _ := rpm.Parse("1.99")
				Expect(v1.Compare(v2)).To(Equal(1))
			})

			It("should compare 2.0 > 1.999", func() {
				v1, _ := rpm.Parse("2.0")
				v2, _ := rpm.Parse("1.999")
				Expect(v1.Compare(v2)).To(Equal(1))
			})
		})

		Context("when handling multi-digit numbers", func() {
			It("should compare 10.0 > 9.0", func() {
				v1, _ := rpm.Parse("10.0")
				v2, _ := rpm.Parse("9.0")
				Expect(v1.Compare(v2)).To(Equal(1))
			})

			It("should compare 1.20.300 > 1.20.299", func() {
				v1, _ := rpm.Parse("1.20.300")
				v2, _ := rpm.Parse("1.20.299")
				Expect(v1.Compare(v2)).To(Equal(1))
			})

			It("should compare 123 > 99", func() {
				v1, _ := rpm.Parse("123")
				v2, _ := rpm.Parse("99")
				Expect(v1.Compare(v2)).To(Equal(1))
			})
		})

		Context("when handling leading zeros", func() {
			It("should treat 01 == 1", func() {
				v1, _ := rpm.Parse("01")
				v2, _ := rpm.Parse("1")
				Expect(v1.Compare(v2)).To(Equal(0))
			})

			It("should treat 001.002 == 1.2", func() {
				v1, _ := rpm.Parse("001.002")
				v2, _ := rpm.Parse("1.2")
				Expect(v1.Compare(v2)).To(Equal(0))
			})

			It("should compare 1.0100 > 1.99", func() {
				v1, _ := rpm.Parse("1.0100")
				v2, _ := rpm.Parse("1.99")
				Expect(v1.Compare(v2)).To(Equal(1))
			})
		})

		Context("when handling zeros", func() {
			It("should compare 1.0 < 1.1", func() {
				v1, _ := rpm.Parse("1.0")
				v2, _ := rpm.Parse("1.1")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.0.0 == 1.0", func() {
				v1, _ := rpm.Parse("1.0.0")
				v2, _ := rpm.Parse("1.0")
				Expect(v1.Compare(v2)).To(Equal(0))
			})

			It("should compare 1.0.0.0 == 1.0", func() {
				v1, _ := rpm.Parse("1.0.0.0")
				v2, _ := rpm.Parse("1.0")
				Expect(v1.Compare(v2)).To(Equal(0))
			})
		})
	})

	Describe("Alpha comparison", func() {
		Context("when comparing alphabetic segments", func() {
			It("should compare 1.a < 1.b", func() {
				v1, _ := rpm.Parse("1.a")
				v2, _ := rpm.Parse("1.b")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.2rc1 > 1.2", func() {
				// "1.2rc1" has more content than "1.2", so it's greater
				// The "rc1" part is an alpha segment that comes after the numeric comparison
				v1, _ := rpm.Parse("1.2rc1")
				v2, _ := rpm.Parse("1.2")
				Expect(v1.Compare(v2)).To(Equal(1))
			})

			It("should compare 1.2.alpha < 1.2.beta", func() {
				v1, _ := rpm.Parse("1.2.alpha")
				v2, _ := rpm.Parse("1.2.beta")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.2.rc < 1.2.release", func() {
				v1, _ := rpm.Parse("1.2.rc")
				v2, _ := rpm.Parse("1.2.release")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})
		})

		Context("when comparing case sensitivity", func() {
			It("should compare case-sensitively (a > A)", func() {
				v1, _ := rpm.Parse("1.a")
				v2, _ := rpm.Parse("1.A")
				// Lowercase 'a' (ASCII 97) > uppercase 'A' (ASCII 65)
				Expect(v1.Compare(v2)).To(Equal(1))
			})

			It("should compare abc > ABC", func() {
				v1, _ := rpm.Parse("1.abc")
				v2, _ := rpm.Parse("1.ABC")
				Expect(v1.Compare(v2)).To(Equal(1))
			})
		})
	})

	Describe("Mixed comparison", func() {
		Context("when comparing mixed numeric and alpha", func() {
			It("should compare 1.2a3 properly", func() {
				v1, _ := rpm.Parse("1.2a3")
				v2, _ := rpm.Parse("1.2a4")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should handle transitions (1.2.3a < 1.2.3b)", func() {
				v1, _ := rpm.Parse("1.2.3a")
				v2, _ := rpm.Parse("1.2.3b")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.2a < 1.2b", func() {
				v1, _ := rpm.Parse("1.2a")
				v2, _ := rpm.Parse("1.2b")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.2.3a4 < 1.2.3a5", func() {
				v1, _ := rpm.Parse("1.2.3a4")
				v2, _ := rpm.Parse("1.2.3a5")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.2.3a > 1.2.3", func() {
				// "1.2.3a" has more content (the 'a') than "1.2.3"
				// Alpha segments after the version make it greater
				v1, _ := rpm.Parse("1.2.3a")
				v2, _ := rpm.Parse("1.2.3")
				Expect(v1.Compare(v2)).To(Equal(1))
			})
		})

		Context("when numeric vs alpha segments", func() {
			It("should consider numeric > alpha (1.2.1 > 1.2.a)", func() {
				v1, _ := rpm.Parse("1.2.1")
				v2, _ := rpm.Parse("1.2.a")
				// Numeric segments are always newer than alpha
				Expect(v1.Compare(v2)).To(Equal(1))
			})

			It("should compare 1.0.0 > 1.0.rc", func() {
				v1, _ := rpm.Parse("1.0.0")
				v2, _ := rpm.Parse("1.0.rc")
				Expect(v1.Compare(v2)).To(Equal(1))
			})
		})

		Context("when handling dots", func() {
			It("should treat 1.0a == 1.0.a (dots don't affect)", func() {
				v1, _ := rpm.Parse("1.0a")
				v2, _ := rpm.Parse("1.0.a")
				Expect(v1.Compare(v2)).To(Equal(0))
			})

			It("should compare segments correctly across dots", func() {
				v1, _ := rpm.Parse("1.2.3")
				v2, _ := rpm.Parse("1.2.4")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})
		})
	})

	Describe("Edge cases", func() {
		Context("when handling tilde for pre-releases", func() {
			It("should compare 1.0~rc1 < 1.0", func() {
				v1, _ := rpm.Parse("1.0~rc1")
				v2, _ := rpm.Parse("1.0")
				// Tilde sorts before anything (pre-release)
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.0~alpha < 1.0~beta", func() {
				v1, _ := rpm.Parse("1.0~alpha")
				v2, _ := rpm.Parse("1.0~beta")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.0~rc1 < 1.0~rc2", func() {
				v1, _ := rpm.Parse("1.0~rc1")
				v2, _ := rpm.Parse("1.0~rc2")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.0~rc < 1.0", func() {
				v1, _ := rpm.Parse("1.0~rc")
				v2, _ := rpm.Parse("1.0")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})
		})

		Context("when handling dist tags", func() {
			It("should compare 1.el8 < 1.el9", func() {
				v1, _ := rpm.Parse("1.el8")
				v2, _ := rpm.Parse("1.el9")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.0-1.el7 < 1.0-1.el8", func() {
				v1, _ := rpm.Parse("1.0-1.el7")
				v2, _ := rpm.Parse("1.0-1.el8")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.0-1.fc38 < 1.0-1.fc39", func() {
				v1, _ := rpm.Parse("1.0-1.fc38")
				v2, _ := rpm.Parse("1.0-1.fc39")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare complex dist tags", func() {
				v1, _ := rpm.Parse("1.0-1.el8_6")
				v2, _ := rpm.Parse("1.0-1.el8_7")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})
		})

		Context("when handling underscores", func() {
			It("should compare versions with underscores", func() {
				v1, _ := rpm.Parse("1.0_1")
				v2, _ := rpm.Parse("1.0_2")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should handle el8_6 vs el8_7", func() {
				v1, _ := rpm.Parse("1.el8_6")
				v2, _ := rpm.Parse("1.el8_7")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})
		})

		Context("when handling empty and missing parts", func() {
			It("should compare 1.0 vs 1.0-0 correctly", func() {
				v1, _ := rpm.Parse("1.0")
				v2, _ := rpm.Parse("1.0-0")
				// Empty release < "0"
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should handle longer vs shorter versions", func() {
				v1, _ := rpm.Parse("1.0")
				v2, _ := rpm.Parse("1.0.1")
				// 1.0 == 1.0.0 < 1.0.1
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should handle much longer version", func() {
				v1, _ := rpm.Parse("1.0.0.0.0.1")
				v2, _ := rpm.Parse("1.0")
				// 1.0.0.0.0.1 > 1.0 (has more non-zero segments)
				Expect(v1.Compare(v2)).To(Equal(1))
			})
		})

		Context("when handling special characters", func() {
			It("should handle plus signs", func() {
				v1, _ := rpm.Parse("1.0+git")
				v2, _ := rpm.Parse("1.0+git2")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should handle dashes in version part", func() {
				v1, _ := rpm.Parse("1.0-alpha-1")
				v2, _ := rpm.Parse("1.0-beta-1")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})
		})
	})

	Describe("Comprehensive test matrix", func() {
		type testCase struct {
			v1       string
			v2       string
			expected int
			desc     string
		}

		DescribeTable("version comparisons",
			func(tc testCase) {
				ver1, err1 := rpm.Parse(tc.v1)
				ver2, err2 := rpm.Parse(tc.v2)
				Expect(err1).ToNot(HaveOccurred(), "Failed to parse v1: %s", tc.v1)
				Expect(err2).ToNot(HaveOccurred(), "Failed to parse v2: %s", tc.v2)
				result := ver1.Compare(ver2)
				Expect(result).To(Equal(tc.expected), "Expected %s %s %s but got %d",
					tc.v1, cmpSymbol(tc.expected), tc.v2, result)
			},
			Entry("equal simple", testCase{"1.2", "1.2", 0, "equal"}),
			Entry("equal complex", testCase{"1.2.3-4", "1.2.3-4", 0, "equal"}),
			Entry("less simple", testCase{"1.2", "1.3", -1, "less"}),
			Entry("less complex", testCase{"1.2.3", "1.2.4", -1, "less"}),
			Entry("greater simple", testCase{"1.3", "1.2", 1, "greater"}),
			Entry("numeric not string", testCase{"1.10", "1.9", 1, "numeric"}),
			Entry("epoch wins", testCase{"2:1.0", "1:9999", 1, "epoch"}),
			Entry("epoch less", testCase{"1:1.0", "2:1.0", -1, "epoch"}),
			Entry("release less", testCase{"1.0-1", "1.0-2", -1, "release"}),
			Entry("el8 vs el9", testCase{"1.2.3-4.el8", "1.2.3-4.el9", -1, "dist"}),
			Entry("tilde pre-release", testCase{"1.0~rc1", "1.0", -1, "tilde"}),
			Entry("dots equal", testCase{"1.0a", "1.0.a", 0, "dots"}),
			Entry("missing release", testCase{"1.0", "1.0-0", -1, "release"}),
			Entry("alpha less", testCase{"1.a", "1.b", -1, "alpha"}),
			Entry("numeric vs alpha", testCase{"1.0.1", "1.0.a", 1, "numeric vs alpha"}),
			Entry("leading zeros", testCase{"01.02", "1.2", 0, "zeros"}),
			Entry("longer version", testCase{"1.0.1", "1.0", 1, "longer"}),
			Entry("real world 1", testCase{"2:1.1.1k-7.el8_6", "2:1.1.1k-8.el8_6", -1, "openssl"}),
			Entry("real world 2", testCase{"2.27-34.el7", "2.27-35.el7", -1, "glibc"}),
		)
	})
})

// Helper function to convert comparison result to symbol
func cmpSymbol(cmp int) string {
	switch cmp {
	case -1:
		return "<"
	case 0:
		return "=="
	case 1:
		return ">"
	default:
		return "?"
	}
}
