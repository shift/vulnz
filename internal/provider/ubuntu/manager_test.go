package ubuntu_test

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider/ubuntu"
)

func writeTestCVEFile(dir, filename, content string) {
	Expect(os.MkdirAll(dir, 0755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, filename), []byte(content), 0644)).To(Succeed())
}

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

var _ = Describe("Manager", func() {
	Describe("MapParsed", func() {
		Context("with multiple releases and packages", func() {
			It("should create vulnerability records per namespace", func() {
				cveFile := ubuntu.CVEFile{
					Name:        "CVE-2024-10001",
					Priority:    "high",
					Description: "A test vulnerability",
					Patches: []ubuntu.Patch{
						{Distro: "focal", Package: "curl", Status: "released", Version: "7.68.0-1ubuntu2.3"},
						{Distro: "jammy", Package: "curl", Status: "needed"},
						{Distro: "noble", Package: "curl", Status: "not-affected"},
						{Distro: "bionic", Package: "curl", Status: "DNE"},
						{Distro: "focal", Package: "libcurl4", Status: "needs-triage"},
						{Distro: "jammy", Package: "libcurl4", Status: "released", Version: "7.81.0-1ubuntu1.5"},
						{Distro: "unknownrel", Package: "curl", Status: "needed"},
					},
				}

				vulns := ubuntu.MapParsed(cveFile, testLogger)

				namespaces := make(map[string]bool)
				for _, v := range vulns {
					namespaces[v.NamespaceName] = true
				}

				Expect(namespaces).To(HaveKey("ubuntu:20.04"))
				Expect(namespaces).To(HaveKey("ubuntu:22.04"))
				Expect(namespaces).To(HaveKey("ubuntu:24.04"))
				Expect(namespaces).To(HaveKey("ubuntu:18.04"))
				Expect(namespaces).NotTo(HaveKey("ubuntu:unknownrel"))
			})

			It("should correctly set severity from priority", func() {
				cveFile := ubuntu.CVEFile{
					Name:        "CVE-2024-10002",
					Priority:    "critical",
					Description: "Critical vuln",
					Patches: []ubuntu.Patch{
						{Distro: "focal", Package: "pkg1", Status: "needed"},
					},
				}

				vulns := ubuntu.MapParsed(cveFile, testLogger)
				Expect(vulns).To(HaveLen(1))
				Expect(vulns[0].Severity).To(Equal("Critical"))
			})

			It("should use package-level priority when higher", func() {
				cveFile := ubuntu.CVEFile{
					Name:        "CVE-2024-10003",
					Priority:    "low",
					Description: "Low priority CVE",
					Patches: []ubuntu.Patch{
						{Distro: "focal", Package: "pkg1", Status: "needed", Priority: "critical"},
					},
				}

				vulns := ubuntu.MapParsed(cveFile, testLogger)
				Expect(vulns).To(HaveLen(1))
				Expect(vulns[0].Severity).To(Equal("Critical"))
			})
		})

		Context("with released status", func() {
			It("should set version from patch", func() {
				cveFile := ubuntu.CVEFile{
					Name:        "CVE-2024-10004",
					Priority:    "medium",
					Description: "Test",
					Patches: []ubuntu.Patch{
						{Distro: "jammy", Package: "openssl", Status: "released", Version: "3.0.2-0ubuntu1.2"},
					},
				}

				vulns := ubuntu.MapParsed(cveFile, testLogger)
				Expect(vulns).To(HaveLen(1))
				Expect(vulns[0].FixedIn).To(HaveLen(1))
				Expect(vulns[0].FixedIn[0].Name).To(Equal("openssl"))
				Expect(vulns[0].FixedIn[0].Version).To(Equal("3.0.2-0ubuntu1.2"))
				Expect(vulns[0].FixedIn[0].VersionFormat).To(Equal("dpkg"))
			})

			It("should skip released patches with no version", func() {
				cveFile := ubuntu.CVEFile{
					Name:        "CVE-2024-10005",
					Priority:    "medium",
					Description: "Test",
					Patches: []ubuntu.Patch{
						{Distro: "focal", Package: "pkg1", Status: "released", Version: ""},
					},
				}

				vulns := ubuntu.MapParsed(cveFile, testLogger)
				Expect(vulns).To(HaveLen(1))
				Expect(vulns[0].FixedIn).To(BeEmpty())
			})
		})

		Context("with vulnerable statuses", func() {
			It("should create FixedIn with None version for needed status", func() {
				cveFile := ubuntu.CVEFile{
					Name:        "CVE-2024-10006",
					Priority:    "medium",
					Description: "Test",
					Patches: []ubuntu.Patch{
						{Distro: "focal", Package: "pkg1", Status: "needed"},
					},
				}

				vulns := ubuntu.MapParsed(cveFile, testLogger)
				Expect(vulns).To(HaveLen(1))
				Expect(vulns[0].FixedIn).To(HaveLen(1))
				Expect(vulns[0].FixedIn[0].Version).To(Equal("None"))
			})

			It("should create FixedIn with None version for needs-triage status", func() {
				cveFile := ubuntu.CVEFile{
					Name:        "CVE-2024-10007",
					Priority:    "medium",
					Description: "Test",
					Patches: []ubuntu.Patch{
						{Distro: "jammy", Package: "pkg1", Status: "needs-triage"},
					},
				}

				vulns := ubuntu.MapParsed(cveFile, testLogger)
				Expect(vulns).To(HaveLen(1))
				Expect(vulns[0].FixedIn).To(HaveLen(1))
				Expect(vulns[0].FixedIn[0].Version).To(Equal("None"))
			})

			It("should not create FixedIn for ignored status (not vulnerable)", func() {
				cveFile := ubuntu.CVEFile{
					Name:        "CVE-2024-10008",
					Priority:    "medium",
					Description: "Test",
					Patches: []ubuntu.Patch{
						{Distro: "focal", Package: "pkg1", Status: "ignored"},
					},
				}

				vulns := ubuntu.MapParsed(cveFile, testLogger)
				Expect(vulns).To(HaveLen(1))
				Expect(vulns[0].FixedIn).To(BeEmpty())
			})
		})

		Context("with skipped statuses", func() {
			It("should skip not-affected patches", func() {
				cveFile := ubuntu.CVEFile{
					Name:        "CVE-2024-10009",
					Priority:    "medium",
					Description: "Test",
					Patches: []ubuntu.Patch{
						{Distro: "focal", Package: "pkg1", Status: "not-affected"},
					},
				}

				vulns := ubuntu.MapParsed(cveFile, testLogger)
				Expect(vulns).To(HaveLen(1))
				Expect(vulns[0].FixedIn).To(BeEmpty())
			})

			It("should skip DNE patches", func() {
				cveFile := ubuntu.CVEFile{
					Name:        "CVE-2024-10010",
					Priority:    "medium",
					Description: "Test",
					Patches: []ubuntu.Patch{
						{Distro: "focal", Package: "pkg1", Status: "DNE"},
					},
				}

				vulns := ubuntu.MapParsed(cveFile, testLogger)
				Expect(vulns).To(HaveLen(1))
				Expect(vulns[0].FixedIn).To(BeEmpty())
			})
		})

		Context("with empty CVE name", func() {
			It("should return nil", func() {
				cveFile := ubuntu.CVEFile{
					Name:     "",
					Priority: "high",
					Patches: []ubuntu.Patch{
						{Distro: "focal", Package: "pkg1", Status: "needed"},
					},
				}

				vulns := ubuntu.MapParsed(cveFile, testLogger)
				Expect(vulns).To(BeNil())
			})
		})
	})

	Describe("parsing CVE files from directory", func() {
		var tempDir string

		BeforeEach(func() {
			var err error
			tempDir, err = os.MkdirTemp("", "ubuntu-manager-test-*")
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			os.RemoveAll(tempDir)
		})

		It("should parse CVE files from active and retired directories", func() {
			activeCVE := `CVE-2024-20001
Priority: high
Description:
    A vulnerability in the kernel

focal_linux: needs-triage
jammy_linux: released (5.15.0-100-generic)
`
			retiredCVE := `CVE-2024-20002
Priority: low
Description:
    An old vulnerability

focal_oldpkg: needed
`
			writeTestCVEFile(filepath.Join(tempDir, "active"), "CVE-2024-20001", activeCVE)
			writeTestCVEFile(filepath.Join(tempDir, "retired"), "CVE-2024-20002", retiredCVE)

			vulns, err := ubuntu.ParseCVEFilesFromDir(tempDir, testLogger)
			Expect(err).NotTo(HaveOccurred())
			Expect(vulns).NotTo(BeEmpty())

			cveNames := make(map[string]bool)
			for _, v := range vulns {
				cveNames[v.Name] = true
			}
			Expect(cveNames).To(HaveKey("CVE-2024-20001"))
			Expect(cveNames).To(HaveKey("CVE-2024-20002"))
		})

		It("should skip non-CVE files", func() {
			writeTestCVEFile(tempDir, "README.md", "not a cve file")
			writeTestCVEFile(tempDir, "CVE-2024-30001", "CVE-2024-30001\nPriority: medium\n\nfocal_pkg: needed\n")

			vulns, err := ubuntu.ParseCVEFilesFromDir(tempDir, testLogger)
			Expect(err).NotTo(HaveOccurred())
			Expect(vulns).NotTo(BeEmpty())

			for _, v := range vulns {
				Expect(v.Name).To(Equal("CVE-2024-30001"))
			}
		})
	})
})

func TestManagerStandalone(t *testing.T) {
	t.Parallel()

	t.Run("parse CVE files from directory", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "ubuntu-manager-standalone-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tempDir)

		activeDir := filepath.Join(tempDir, "active")
		if err := os.MkdirAll(activeDir, 0755); err != nil {
			t.Fatal(err)
		}

		content := "CVE-2024-50001\nPriority: high\n\nfocal_testpkg: released (1.0-1)\njammy_testpkg: needed\n"
		if err := os.WriteFile(filepath.Join(activeDir, "CVE-2024-50001"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		vulns, err := ubuntu.ParseCVEFilesFromDir(tempDir, testLogger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(vulns) == 0 {
			t.Error("expected at least one vulnerability record")
		}

		foundFocal := false
		foundJammy := false
		for _, v := range vulns {
			if v.NamespaceName == "ubuntu:20.04" {
				foundFocal = true
			}
			if v.NamespaceName == "ubuntu:22.04" {
				foundJammy = true
			}
		}
		if !foundFocal {
			t.Error("expected to find ubuntu:20.04 namespace")
		}
		if !foundJammy {
			t.Error("expected to find ubuntu:22.04 namespace")
		}
	})
}
