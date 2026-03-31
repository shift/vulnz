package rpm_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/utils/rpm"
)

var _ = Describe("RPM Version", func() {
	Describe("Parsing", func() {
		Context("when parsing simple versions", func() {
			It("should parse simple version without epoch or release", func() {
				v, err := rpm.Parse("1.2.3")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(0))
				Expect(v.Version).To(Equal("1.2.3"))
				Expect(v.Release).To(Equal(""))
			})

			It("should parse version with dots and numbers", func() {
				v, err := rpm.Parse("2.27.34")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(0))
				Expect(v.Version).To(Equal("2.27.34"))
				Expect(v.Release).To(Equal(""))
			})

			It("should parse version with letters", func() {
				v, err := rpm.Parse("1.1.1k")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(0))
				Expect(v.Version).To(Equal("1.1.1k"))
				Expect(v.Release).To(Equal(""))
			})
		})

		Context("when parsing versions with epoch", func() {
			It("should parse version with epoch 1", func() {
				v, err := rpm.Parse("1:1.2.3")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(1))
				Expect(v.Version).To(Equal("1.2.3"))
				Expect(v.Release).To(Equal(""))
			})

			It("should parse version with epoch 2", func() {
				v, err := rpm.Parse("2:1.0")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(2))
				Expect(v.Version).To(Equal("1.0"))
				Expect(v.Release).To(Equal(""))
			})

			It("should parse version with large epoch", func() {
				v, err := rpm.Parse("999:1.0.0")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(999))
				Expect(v.Version).To(Equal("1.0.0"))
				Expect(v.Release).To(Equal(""))
			})

			It("should reject negative epoch", func() {
				_, err := rpm.Parse("-1:1.0")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("epoch cannot be negative"))
			})

			It("should reject invalid epoch", func() {
				_, err := rpm.Parse("abc:1.0")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid epoch"))
			})
		})

		Context("when parsing versions with release", func() {
			It("should parse version with simple release", func() {
				v, err := rpm.Parse("1.2.3-4")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(0))
				Expect(v.Version).To(Equal("1.2.3"))
				Expect(v.Release).To(Equal("4"))
			})

			It("should parse version with el8 release", func() {
				v, err := rpm.Parse("1.2.3-4.el8")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(0))
				Expect(v.Version).To(Equal("1.2.3"))
				Expect(v.Release).To(Equal("4.el8"))
			})

			It("should parse version with el8_6 release", func() {
				v, err := rpm.Parse("1.1.1k-7.el8_6")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(0))
				Expect(v.Version).To(Equal("1.1.1k"))
				Expect(v.Release).To(Equal("7.el8_6"))
			})

			It("should parse version with fc39 release", func() {
				v, err := rpm.Parse("1.0-1.fc39")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(0))
				Expect(v.Version).To(Equal("1.0"))
				Expect(v.Release).To(Equal("1.fc39"))
			})

			It("should handle version with dash in version part", func() {
				v, err := rpm.Parse("1.2-rc1-1.el8")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(0))
				Expect(v.Version).To(Equal("1.2-rc1"))
				Expect(v.Release).To(Equal("1.el8"))
			})
		})

		Context("when parsing complete versions", func() {
			It("should parse epoch:version-release", func() {
				v, err := rpm.Parse("2:1.2.3-4.el8")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(2))
				Expect(v.Version).To(Equal("1.2.3"))
				Expect(v.Release).To(Equal("4.el8"))
			})

			It("should parse real-world openssl version", func() {
				v, err := rpm.Parse("2:1.1.1k-7.el8_6")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(2))
				Expect(v.Version).To(Equal("1.1.1k"))
				Expect(v.Release).To(Equal("7.el8_6"))
			})

			It("should parse real-world glibc version", func() {
				v, err := rpm.Parse("2.27-34.base.el7")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(0))
				Expect(v.Version).To(Equal("2.27"))
				Expect(v.Release).To(Equal("34.base.el7"))
			})
		})

		Context("when parsing invalid formats", func() {
			It("should reject empty string", func() {
				_, err := rpm.Parse("")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("empty version string"))
			})

			It("should reject version without version part", func() {
				_, err := rpm.Parse("2:")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("version part cannot be empty"))
			})
		})
	})

	Describe("String representation", func() {
		Context("when formatting versions", func() {
			It("should format simple version without epoch or release", func() {
				v := &rpm.Version{Epoch: 0, Version: "1.2.3", Release: ""}
				Expect(v.String()).To(Equal("1.2.3"))
			})

			It("should format version with epoch", func() {
				v := &rpm.Version{Epoch: 2, Version: "1.2.3", Release: ""}
				Expect(v.String()).To(Equal("2:1.2.3"))
			})

			It("should format version with release but no epoch", func() {
				v := &rpm.Version{Epoch: 0, Version: "1.2.3", Release: "4.el8"}
				Expect(v.String()).To(Equal("1.2.3-4.el8"))
			})

			It("should format complete version with epoch and release", func() {
				v := &rpm.Version{Epoch: 2, Version: "1.2.3", Release: "4.el8"}
				Expect(v.String()).To(Equal("2:1.2.3-4.el8"))
			})
		})

		Context("when round-tripping parse and string", func() {
			It("should round-trip simple version", func() {
				original := "1.2.3"
				v, err := rpm.Parse(original)
				Expect(err).ToNot(HaveOccurred())
				Expect(v.String()).To(Equal(original))
			})

			It("should round-trip version with release", func() {
				original := "1.2.3-4.el8"
				v, err := rpm.Parse(original)
				Expect(err).ToNot(HaveOccurred())
				Expect(v.String()).To(Equal(original))
			})

			It("should round-trip complete version", func() {
				original := "2:1.2.3-4.el8"
				v, err := rpm.Parse(original)
				Expect(err).ToNot(HaveOccurred())
				Expect(v.String()).To(Equal(original))
			})
		})
	})

	Describe("Comparison", func() {
		Context("when comparing equal versions", func() {
			It("should consider identical versions equal", func() {
				v1, _ := rpm.Parse("1.2.3")
				v2, _ := rpm.Parse("1.2.3")
				Expect(v1.Compare(v2)).To(Equal(0))
				Expect(v1.Equal(v2)).To(BeTrue())
			})

			It("should consider versions with same epoch, version, and release equal", func() {
				v1, _ := rpm.Parse("2:1.2.3-4.el8")
				v2, _ := rpm.Parse("2:1.2.3-4.el8")
				Expect(v1.Compare(v2)).To(Equal(0))
				Expect(v1.Equal(v2)).To(BeTrue())
			})

			It("should consider version without release less than version with release 0", func() {
				v1, _ := rpm.Parse("1.0")
				v2, _ := rpm.Parse("1.0-0")
				// Empty release is treated as less than "0"
				Expect(v1.Compare(v2)).To(Equal(-1))
			})
		})

		Context("when comparing by epoch", func() {
			It("should consider higher epoch greater regardless of version", func() {
				v1, _ := rpm.Parse("2:1.0")
				v2, _ := rpm.Parse("1:9999")
				Expect(v1.Compare(v2)).To(Equal(1))
				Expect(v1.Greater(v2)).To(BeTrue())
				Expect(v2.Less(v1)).To(BeTrue())
			})

			It("should compare epoch 1 > epoch 0", func() {
				v1, _ := rpm.Parse("1:1.0")
				v2, _ := rpm.Parse("1.0")
				Expect(v1.Compare(v2)).To(Equal(1))
				Expect(v1.Greater(v2)).To(BeTrue())
			})

			It("should compare epoch 3 > epoch 1", func() {
				v1, _ := rpm.Parse("3:1.0")
				v2, _ := rpm.Parse("1:1.0")
				Expect(v1.Compare(v2)).To(Equal(1))
			})
		})

		Context("when comparing by version", func() {
			It("should compare 1.2 < 1.3", func() {
				v1, _ := rpm.Parse("1.2")
				v2, _ := rpm.Parse("1.3")
				Expect(v1.Compare(v2)).To(Equal(-1))
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare 1.2.3 < 1.2.4", func() {
				v1, _ := rpm.Parse("1.2.3")
				v2, _ := rpm.Parse("1.2.4")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 2.0 > 1.9", func() {
				v1, _ := rpm.Parse("2.0")
				v2, _ := rpm.Parse("1.9")
				Expect(v1.Compare(v2)).To(Equal(1))
			})
		})

		Context("when comparing by release", func() {
			It("should compare releases when versions are equal", func() {
				v1, _ := rpm.Parse("1.0-1")
				v2, _ := rpm.Parse("1.0-2")
				Expect(v1.Compare(v2)).To(Equal(-1))
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare 1.2.3-4.el8 < 1.2.3-5.el8", func() {
				v1, _ := rpm.Parse("1.2.3-4.el8")
				v2, _ := rpm.Parse("1.2.3-5.el8")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should compare 1.2.3-4.el8 < 1.2.3-4.el9", func() {
				v1, _ := rpm.Parse("1.2.3-4.el8")
				v2, _ := rpm.Parse("1.2.3-4.el9")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})
		})

		Context("when handling missing components", func() {
			It("should handle missing release in v1", func() {
				v1, _ := rpm.Parse("1.0")
				v2, _ := rpm.Parse("1.0-1")
				// "1.0" is equivalent to "1.0-0", which is less than "1.0-1"
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should handle missing release in v2", func() {
				v1, _ := rpm.Parse("1.0-1")
				v2, _ := rpm.Parse("1.0")
				Expect(v1.Compare(v2)).To(Equal(1))
			})
		})

		Context("when handling nil versions", func() {
			It("should handle nil v1", func() {
				var v1 *rpm.Version
				v2, _ := rpm.Parse("1.0")
				Expect(v1.Compare(v2)).To(Equal(-1))
			})

			It("should handle nil v2", func() {
				v1, _ := rpm.Parse("1.0")
				var v2 *rpm.Version
				Expect(v1.Compare(v2)).To(Equal(1))
			})

			It("should handle both nil", func() {
				var v1, v2 *rpm.Version
				Expect(v1.Compare(v2)).To(Equal(0))
			})
		})
	})

	Describe("Validation", func() {
		Context("when validating version strings", func() {
			It("should validate simple version", func() {
				err := rpm.Validate("1.2.3")
				Expect(err).ToNot(HaveOccurred())
			})

			It("should validate version with epoch", func() {
				err := rpm.Validate("2:1.2.3")
				Expect(err).ToNot(HaveOccurred())
			})

			It("should validate version with release", func() {
				err := rpm.Validate("1.2.3-4.el8")
				Expect(err).ToNot(HaveOccurred())
			})

			It("should reject empty string", func() {
				err := rpm.Validate("")
				Expect(err).To(HaveOccurred())
			})

			It("should reject invalid epoch", func() {
				err := rpm.Validate("abc:1.0")
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when validating epochs", func() {
			It("should accept epoch 0", func() {
				Expect(rpm.IsValidEpoch(0)).To(BeTrue())
			})

			It("should accept positive epochs", func() {
				Expect(rpm.IsValidEpoch(1)).To(BeTrue())
				Expect(rpm.IsValidEpoch(999)).To(BeTrue())
			})

			It("should reject negative epochs", func() {
				Expect(rpm.IsValidEpoch(-1)).To(BeFalse())
			})
		})

		Context("when validating version strings", func() {
			It("should accept valid versions", func() {
				Expect(rpm.IsValidVersion("1.2.3")).To(BeTrue())
				Expect(rpm.IsValidVersion("1.0a")).To(BeTrue())
				Expect(rpm.IsValidVersion("1.2.3rc1")).To(BeTrue())
			})

			It("should reject empty version", func() {
				Expect(rpm.IsValidVersion("")).To(BeFalse())
			})
		})
	})

	Describe("Constructor functions", func() {
		Context("when using MustParse", func() {
			It("should parse valid version", func() {
				v := rpm.MustParse("1.2.3-4.el8")
				Expect(v.Version).To(Equal("1.2.3"))
				Expect(v.Release).To(Equal("4.el8"))
			})

			It("should panic on invalid version", func() {
				Expect(func() {
					rpm.MustParse("")
				}).To(Panic())
			})
		})

		Context("when using New", func() {
			It("should create version from components", func() {
				v, err := rpm.New(2, "1.2.3", "4.el8")
				Expect(err).ToNot(HaveOccurred())
				Expect(v.Epoch).To(Equal(2))
				Expect(v.Version).To(Equal("1.2.3"))
				Expect(v.Release).To(Equal("4.el8"))
			})

			It("should reject invalid epoch", func() {
				_, err := rpm.New(-1, "1.2.3", "4.el8")
				Expect(err).To(HaveOccurred())
			})

			It("should reject empty version", func() {
				_, err := rpm.New(0, "", "4.el8")
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when using MustNew", func() {
			It("should create version from valid components", func() {
				v := rpm.MustNew(2, "1.2.3", "4.el8")
				Expect(v.Epoch).To(Equal(2))
				Expect(v.Version).To(Equal("1.2.3"))
				Expect(v.Release).To(Equal("4.el8"))
			})

			It("should panic on invalid components", func() {
				Expect(func() {
					rpm.MustNew(-1, "1.2.3", "4.el8")
				}).To(Panic())
			})
		})
	})
})
