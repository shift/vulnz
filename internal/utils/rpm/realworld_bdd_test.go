package rpm_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/utils/rpm"
)

var _ = Describe("Real-World RPM Comparisons", func() {
	Describe("OpenSSL versions", func() {
		Context("when comparing RHEL 8 OpenSSL versions", func() {
			It("should compare 1.1.1k-7 < 1.1.1k-8", func() {
				v1, _ := rpm.Parse("2:1.1.1k-7.el8_6")
				v2, _ := rpm.Parse("2:1.1.1k-8.el8_6")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare el8_6 < el8_7", func() {
				v1, _ := rpm.Parse("2:1.1.1k-7.el8_6")
				v2, _ := rpm.Parse("2:1.1.1k-7.el8_7")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare across minor versions", func() {
				v1, _ := rpm.Parse("2:1.1.1k-1.el8")
				v2, _ := rpm.Parse("2:1.1.1l-1.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})

		Context("when comparing OpenSSL 1.x vs 3.x", func() {
			It("should compare 1.1.1 < 3.0.0", func() {
				v1, _ := rpm.Parse("1:1.1.1k-1")
				v2, _ := rpm.Parse("1:3.0.0-1")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should handle epoch changes", func() {
				// OpenSSL 3.x might use different epoch
				v1, _ := rpm.Parse("2:1.1.1k-1")
				v2, _ := rpm.Parse("3:3.0.0-1")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})

	Describe("Kernel versions", func() {
		Context("when comparing RHEL kernel versions", func() {
			It("should compare kernel 4.18.0-372 < 4.18.0-373", func() {
				v1, _ := rpm.Parse("4.18.0-372.el8")
				v2, _ := rpm.Parse("4.18.0-373.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare kernel with build numbers", func() {
				v1, _ := rpm.Parse("4.18.0-372.32.1.el8_6")
				v2, _ := rpm.Parse("4.18.0-372.40.1.el8_6")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare across RHEL versions", func() {
				v1, _ := rpm.Parse("3.10.0-1160.el7")
				v2, _ := rpm.Parse("4.18.0-372.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should handle kernel with architecture tags", func() {
				v1, _ := rpm.Parse("5.14.0-284.el9")
				v2, _ := rpm.Parse("5.14.0-284.11.1.el9_2")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})

		Context("when comparing Fedora kernel versions", func() {
			It("should compare fc38 < fc39", func() {
				v1, _ := rpm.Parse("6.2.15-300.fc38")
				v2, _ := rpm.Parse("6.2.15-300.fc39")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare kernel versions across Fedora releases", func() {
				v1, _ := rpm.Parse("6.2.0-100.fc38")
				v2, _ := rpm.Parse("6.3.0-0.fc39")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})

	Describe("glibc versions", func() {
		Context("when comparing RHEL 7 glibc", func() {
			It("should compare 2.27-34 < 2.27-35", func() {
				v1, _ := rpm.Parse("2.27-34.base.el7")
				v2, _ := rpm.Parse("2.27-35.base.el7")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare base vs updates", func() {
				v1, _ := rpm.Parse("2.17-317.el7")
				v2, _ := rpm.Parse("2.17-326.el7_9")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})

		Context("when comparing glibc across RHEL versions", func() {
			It("should compare RHEL 7 vs RHEL 8 glibc", func() {
				v1, _ := rpm.Parse("2.17-326.el7")
				v2, _ := rpm.Parse("2.28-164.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare RHEL 8 vs RHEL 9 glibc", func() {
				v1, _ := rpm.Parse("2.28-164.el8")
				v2, _ := rpm.Parse("2.34-28.el9")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})

	Describe("Python packages", func() {
		Context("when comparing python3 versions", func() {
			It("should compare python 3.6 < 3.9", func() {
				v1, _ := rpm.Parse("3.6.8-45.el8")
				v2, _ := rpm.Parse("3.9.7-1.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare with rc versions", func() {
				v1, _ := rpm.Parse("3.9.0~rc1-1")
				v2, _ := rpm.Parse("3.9.0-1")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})

		Context("when comparing pip versions", func() {
			It("should compare pip updates", func() {
				v1, _ := rpm.Parse("21.2.3-1.el8")
				v2, _ := rpm.Parse("21.2.4-1.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})

	Describe("Apache and Nginx", func() {
		Context("when comparing httpd versions", func() {
			It("should compare Apache 2.4.x versions", func() {
				v1, _ := rpm.Parse("2.4.37-47.el8")
				v2, _ := rpm.Parse("2.4.37-51.el8_7")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare across minor versions", func() {
				v1, _ := rpm.Parse("2.4.37-1")
				v2, _ := rpm.Parse("2.4.51-1")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})

		Context("when comparing nginx versions", func() {
			It("should compare nginx 1.20 < 1.22", func() {
				v1, _ := rpm.Parse("1:1.20.1-1.el8")
				v2, _ := rpm.Parse("1:1.22.0-1.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should handle module versions", func() {
				v1, _ := rpm.Parse("1:1.14.1-9.module+el8.0.0+4108")
				v2, _ := rpm.Parse("1:1.14.1-9.module+el8.4.0+20239")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})

	Describe("Database packages", func() {
		Context("when comparing PostgreSQL versions", func() {
			It("should compare postgres 13 < 14", func() {
				v1, _ := rpm.Parse("13.7-1.el8")
				v2, _ := rpm.Parse("14.3-1.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare within same major version", func() {
				v1, _ := rpm.Parse("13.7-1.el8")
				v2, _ := rpm.Parse("13.8-1.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})

		Context("when comparing MySQL/MariaDB versions", func() {
			It("should compare MariaDB versions", func() {
				v1, _ := rpm.Parse("3:10.3.28-1.el8")
				v2, _ := rpm.Parse("3:10.3.32-1.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare across major versions", func() {
				v1, _ := rpm.Parse("1:10.3.32-1")
				v2, _ := rpm.Parse("1:10.5.16-1")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})

	Describe("RHEL dist tags", func() {
		Context("when comparing dist tag variations", func() {
			It("should compare el7 < el8", func() {
				v1, _ := rpm.Parse("1.0-1.el7")
				v2, _ := rpm.Parse("1.0-1.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare el8 < el9", func() {
				v1, _ := rpm.Parse("1.0-1.el8")
				v2, _ := rpm.Parse("1.0-1.el9")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare el8_6 < el8_7", func() {
				v1, _ := rpm.Parse("1.0-1.el8_6")
				v2, _ := rpm.Parse("1.0-1.el8_7")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare el9_0 < el9_1", func() {
				v1, _ := rpm.Parse("1.0-1.el9_0")
				v2, _ := rpm.Parse("1.0-1.el9_1")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})

		Context("when comparing base vs minor updates", func() {
			It("should compare base el8 < el8_6", func() {
				v1, _ := rpm.Parse("1.0-1.el8")
				v2, _ := rpm.Parse("1.0-1.el8_6")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})

	Describe("Fedora dist tags", func() {
		Context("when comparing Fedora releases", func() {
			It("should compare fc38 < fc39", func() {
				v1, _ := rpm.Parse("1.0-1.fc38")
				v2, _ := rpm.Parse("1.0-1.fc39")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare fc39 < fc40", func() {
				v1, _ := rpm.Parse("1.0-1.fc39")
				v2, _ := rpm.Parse("1.0-1.fc40")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})

	Describe("SUSE versions", func() {
		Context("when comparing SLES versions", func() {
			It("should compare SLES release tags", func() {
				v1, _ := rpm.Parse("1.0-1.sles15")
				v2, _ := rpm.Parse("1.0-2.sles15")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare with sp tags", func() {
				v1, _ := rpm.Parse("1.0-1.sles15sp1")
				v2, _ := rpm.Parse("1.0-1.sles15sp2")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})

	Describe("Oracle Linux versions", func() {
		Context("when comparing OL dist tags", func() {
			It("should compare ol8 versions", func() {
				v1, _ := rpm.Parse("1.0-1.0.1.el8")
				v2, _ := rpm.Parse("1.0-1.0.2.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})

	Describe("Pre-release and beta versions", func() {
		Context("when comparing pre-release markers", func() {
			It("should compare alpha < beta < rc < release", func() {
				v1, _ := rpm.Parse("1.0~alpha1-1")
				v2, _ := rpm.Parse("1.0~beta1-1")
				v3, _ := rpm.Parse("1.0~rc1-1")
				v4, _ := rpm.Parse("1.0-1")

				Expect(v1.Less(v2)).To(BeTrue())
				Expect(v2.Less(v3)).To(BeTrue())
				Expect(v3.Less(v4)).To(BeTrue())
			})

			It("should compare rc versions", func() {
				v1, _ := rpm.Parse("2.0~rc1-1")
				v2, _ := rpm.Parse("2.0~rc2-1")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})

	Describe("Security updates", func() {
		Context("when comparing CVE fix versions", func() {
			It("should detect vulnerable version", func() {
				installed, _ := rpm.Parse("2:1.1.1k-7.el8_6")
				fixed, _ := rpm.Parse("2:1.1.1k-8.el8_6")

				// Installed version is less than fixed version, so it's vulnerable
				Expect(installed.Less(fixed)).To(BeTrue())
			})

			It("should detect patched version", func() {
				installed, _ := rpm.Parse("2:1.1.1k-9.el8_6")
				fixed, _ := rpm.Parse("2:1.1.1k-8.el8_6")

				// Installed version is greater than fixed version, so it's patched
				Expect(installed.Greater(fixed)).To(BeTrue())
			})

			It("should detect same version", func() {
				installed, _ := rpm.Parse("2:1.1.1k-8.el8_6")
				fixed, _ := rpm.Parse("2:1.1.1k-8.el8_6")

				// Same version, so it's patched
				Expect(installed.Equal(fixed)).To(BeTrue())
			})
		})
	})

	Describe("Complex real-world scenarios", func() {
		Context("when handling complex version strings", func() {
			It("should compare Java package versions", func() {
				v1, _ := rpm.Parse("1:1.8.0.352.b08-1.el8")
				v2, _ := rpm.Parse("1:1.8.0.362.b08-1.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare systemd versions", func() {
				v1, _ := rpm.Parse("239-58.el8")
				v2, _ := rpm.Parse("239-68.el8_7")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare curl versions", func() {
				v1, _ := rpm.Parse("7.61.1-22.el8")
				v2, _ := rpm.Parse("7.61.1-25.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})

			It("should compare git versions", func() {
				v1, _ := rpm.Parse("2.31.1-2.el8")
				v2, _ := rpm.Parse("2.39.1-1.el8")
				Expect(v1.Less(v2)).To(BeTrue())
			})
		})
	})
})
