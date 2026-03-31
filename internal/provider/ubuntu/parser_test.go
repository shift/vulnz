package ubuntu

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CVE File Parser", func() {
	Describe("parseCVEFile", func() {
		Context("with a complete CVE file", func() {
			It("should parse all fields correctly", func() {
				content := `CVE-2024-12345

Priority: medium
Assigned: 2024-01-15
Published: 2024-02-01
Modified: 2024-03-15
Description:
    A vulnerability was found in the Linux kernel.
    This allows an attacker to gain privileges.

Patches_curl:
    Priority_curl: high
    focal_curl: released (7.68.0-1ubuntu2.3)
    jammy_curl: needs-triage
    noble_curl: not-affected
    bionic_curl: DNE
    focal_libcurl3: released (7.68.0-1ubuntu2.3)
    jammy_libcurl3: needed

Patches_openssl:
    focal_openssl: released (1.1.1f-1ubuntu2.5)
    jammy_openssl: released (3.0.2-0ubuntu1.2)
    xenial_openssl: DNE
`
				cveFile := parseCVEFile("CVE-2024-12345", content)

				Expect(cveFile.Name).To(Equal("CVE-2024-12345"))
				Expect(cveFile.Priority).To(Equal("medium"))
				Expect(cveFile.Description).To(Equal("A vulnerability was found in the Linux kernel. This allows an attacker to gain privileges."))
				Expect(len(cveFile.Patches)).To(BeNumerically(">=", 7))

				var curlPatches []Patch
				for _, p := range cveFile.Patches {
					if p.Package == "curl" {
						curlPatches = append(curlPatches, p)
					}
				}
				Expect(len(curlPatches)).To(BeNumerically(">=", 4))

				var focalCurlPatch *Patch
				for _, p := range curlPatches {
					if p.Distro == "focal" {
						focalCurlPatch = &p
						break
					}
				}
				Expect(focalCurlPatch).NotTo(BeNil())
				Expect(focalCurlPatch.Status).To(Equal("released"))
				Expect(focalCurlPatch.Version).To(Equal("7.68.0-1ubuntu2.3"))
				Expect(focalCurlPatch.Priority).To(Equal("high"))
			})
		})

		Context("with Candidate field", func() {
			It("should override the filename with the Candidate value", func() {
				content := `Candidate: CVE-2024-99999
Priority: high

focal_linux: needs-triage
`
				cveFile := parseCVEFile("CVE-2024-12345", content)
				Expect(cveFile.Name).To(Equal("CVE-2024-99999"))
				Expect(cveFile.Priority).To(Equal("high"))
			})
		})

		Context("with References field", func() {
			It("should parse references list", func() {
				content := `CVE-2024-12345
Priority: low
References:
    https://example.com/advisory1
    https://example.com/advisory2
    https://nvd.nist.gov/vuln/detail/CVE-2024-12345

focal_linux: needed
`
				cveFile := parseCVEFile("CVE-2024-12345", content)
				Expect(cveFile.References).To(HaveLen(3))
				Expect(cveFile.References[0]).To(Equal("https://example.com/advisory1"))
				Expect(cveFile.References[2]).To(ContainSubstring("nvd.nist.gov"))
			})
		})

		Context("with edge cases", func() {
			It("should handle empty content", func() {
				cveFile := parseCVEFile("CVE-2024-12345", "")
				Expect(cveFile.Name).To(Equal("CVE-2024-12345"))
				Expect(cveFile.Priority).To(Equal("Unknown"))
				Expect(cveFile.Patches).To(BeEmpty())
			})

			It("should handle comments", func() {
				content := `# This is a comment
CVE-2024-12345
# Another comment
Priority: high

focal_pkg: needed
`
				cveFile := parseCVEFile("CVE-2024-12345", content)
				Expect(cveFile.Name).To(Equal("CVE-2024-12345"))
				Expect(cveFile.Priority).To(Equal("high"))
				Expect(len(cveFile.Patches)).To(BeNumerically(">=", 1))
			})

			It("should handle missing fields gracefully", func() {
				content := `CVE-2024-12345

focal_linux: needed
jammy_linux: released (5.15.0-100-generic)
`
				cveFile := parseCVEFile("CVE-2024-12345", content)
				Expect(cveFile.Name).To(Equal("CVE-2024-12345"))
				Expect(cveFile.Priority).To(Equal("Unknown"))
				Expect(cveFile.Description).To(BeEmpty())
				Expect(len(cveFile.Patches)).To(BeNumerically(">=", 2))
			})

			It("should handle multiline description", func() {
				content := `CVE-2024-12345
Priority: medium
Description:
    This is a long description
    that spans multiple lines
    about a vulnerability.

focal_pkg: needed
`
				cveFile := parseCVEFile("CVE-2024-12345", content)
				Expect(cveFile.Description).To(ContainSubstring("long description"))
				Expect(cveFile.Description).To(ContainSubstring("multiple lines"))
			})

			It("should handle 'pending' status", func() {
				content := `CVE-2024-12345
Priority: low

focal_pkg: pending (1.0-1)
`
				cveFile := parseCVEFile("CVE-2024-12345", content)
				Expect(len(cveFile.Patches)).To(BeNumerically(">=", 1))
				Expect(cveFile.Patches[0].Status).To(Equal("pending"))
				Expect(cveFile.Patches[0].Version).To(Equal("1.0-1"))
			})

			It("should handle 'ignored' status with version text", func() {
				content := `CVE-2024-12345
Priority: medium

focal_pkg: ignored (end-of-life)
jammy_pkg: ignored
`
				cveFile := parseCVEFile("CVE-2024-12345", content)
				Expect(len(cveFile.Patches)).To(BeNumerically(">=", 2))
			})
		})
	})

	Describe("severity mapping", func() {
		It("should map priority to severity correctly", func() {
			Expect(mapSeverity("low")).To(Equal("Low"))
			Expect(mapSeverity("medium")).To(Equal("Medium"))
			Expect(mapSeverity("high")).To(Equal("High"))
			Expect(mapSeverity("critical")).To(Equal("Critical"))
			Expect(mapSeverity("unknown")).To(Equal("Unknown"))
			Expect(mapSeverity("untriaged")).To(Equal("Unknown"))
			Expect(mapSeverity("")).To(Equal("Unknown"))
			Expect(mapSeverity("foobar")).To(Equal("Unknown"))
		})
	})

	Describe("namespace mapping", func() {
		It("should map release names to versions", func() {
			Expect(mapNamespace("focal")).To(Equal("ubuntu:20.04"))
			Expect(mapNamespace("jammy")).To(Equal("ubuntu:22.04"))
			Expect(mapNamespace("noble")).To(Equal("ubuntu:24.04"))
			Expect(mapNamespace("bionic")).To(Equal("ubuntu:18.04"))
			Expect(mapNamespace("xenial")).To(Equal("ubuntu:16.04"))
			Expect(mapNamespace("plucky")).To(Equal("ubuntu:25.04"))
			Expect(mapNamespace("questing")).To(Equal("ubuntu:25.10"))
		})

		It("should return empty string for unknown releases", func() {
			Expect(mapNamespace("unknownrelease")).To(BeEmpty())
			Expect(mapNamespace("")).To(BeEmpty())
		})
	})

	Describe("patch state checks", func() {
		It("should correctly identify vulnerable states", func() {
			Expect(checkState("needed")).To(BeTrue())
			Expect(checkState("needs-triage")).To(BeTrue())
			Expect(checkState("released")).To(BeTrue())
			Expect(checkState("pending")).To(BeTrue())
			Expect(checkState("active")).To(BeTrue())
			Expect(checkState("deferred")).To(BeTrue())
		})

		It("should correctly identify non-vulnerable states", func() {
			Expect(checkState("DNE")).To(BeFalse())
			Expect(checkState("not-affected")).To(BeFalse())
			Expect(checkState("ignored")).To(BeFalse())
		})
	})

	Describe("release checks", func() {
		It("should correctly identify known releases", func() {
			Expect(checkRelease("focal")).To(BeTrue())
			Expect(checkRelease("jammy")).To(BeTrue())
			Expect(checkRelease("noble")).To(BeTrue())
		})

		It("should return false for unknown releases", func() {
			Expect(checkRelease("unknownrelease")).To(BeFalse())
			Expect(checkRelease("")).To(BeFalse())
		})
	})

	Describe("isCVEFile", func() {
		It("should match valid CVE filenames", func() {
			Expect(IsCVEFile("CVE-2024-12345")).To(BeTrue())
			Expect(IsCVEFile("CVE-2023-1")).To(BeTrue())
			Expect(IsCVEFile("CVE-1999-00001")).To(BeTrue())
		})

		It("should reject invalid filenames", func() {
			Expect(IsCVEFile("not-a-cve")).To(BeFalse())
			Expect(IsCVEFile("cve-2024-12345")).To(BeFalse())
			Expect(IsCVEFile("CVE-2024")).To(BeFalse())
			Expect(IsCVEFile("CVE-2024-12345.txt")).To(BeFalse())
		})
	})
})

func TestParseCVEFileStandalone(t *testing.T) {
	t.Parallel()

	t.Run("basic parsing", func(t *testing.T) {
		content := `CVE-2024-12345
Priority: high
Description:
    Test description

focal_curl: released (1.0.0-1)
jammy_curl: needed
`
		cveFile := parseCVEFile("CVE-2024-12345", content)
		if cveFile.Name != "CVE-2024-12345" {
			t.Errorf("expected name CVE-2024-12345, got %s", cveFile.Name)
		}
		if cveFile.Priority != "high" {
			t.Errorf("expected priority high, got %s", cveFile.Priority)
		}
		if cveFile.Description != "Test description" {
			t.Errorf("expected description 'Test description', got %s", cveFile.Description)
		}
		if len(cveFile.Patches) < 2 {
			t.Errorf("expected at least 2 patches, got %d", len(cveFile.Patches))
		}
	})

	t.Run("empty file", func(t *testing.T) {
		cveFile := parseCVEFile("CVE-2024-12345", "")
		if cveFile.Name != "CVE-2024-12345" {
			t.Errorf("expected default name CVE-2024-12345, got %s", cveFile.Name)
		}
		if cveFile.Priority != "Unknown" {
			t.Errorf("expected default priority Unknown, got %s", cveFile.Priority)
		}
	})
}
