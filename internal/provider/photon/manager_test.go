package photon_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/photon"
)

var _ = Describe("Photon Manager", func() {
	var (
		manager  *photon.Manager
		tempDir  string
		inputDir string
		config   provider.Config
		logger   *slog.Logger
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "photon-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		inputDir = filepath.Join(tempDir, "input")
		Expect(os.MkdirAll(inputDir, 0755)).To(Succeed())

		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "photon",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = photon.NewManagerWithVersions(config, []string{"4.0", "5.0"})
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("parseCVEJSON", func() {
		It("should parse valid CVE JSON entries", func() {
			entries := []map[string]string{
				{
					"cve_id":         "CVE-2023-1234",
					"pkg":            "openssl",
					"version":        "3.0.1",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "PHSA-2024-1234",
				},
				{
					"cve_id":         "CVE-2023-1234",
					"pkg":            "openssl-libs",
					"version":        "3.0.1",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "PHSA-2024-1234",
				},
			}

			data, err := json.Marshal(entries)
			Expect(err).NotTo(HaveOccurred())

			wikiDir := filepath.Join(inputDir, "photon.wiki")
			Expect(os.MkdirAll(wikiDir, 0755)).To(Succeed())

			records, err := manager.MergeRecordsFromJSON(data, "4.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(BeNumerically(">=", 1))
		})

		It("should skip BDSA entries", func() {
			entries := []map[string]string{
				{
					"cve_id":         "BDSA-2023-1234",
					"pkg":            "some-pkg",
					"version":        "1.0",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "BDSA-2023-1234",
				},
				{
					"cve_id":         "CVE-2023-5678",
					"pkg":            "openssl",
					"version":        "3.0.1",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "PHSA-2024-5678",
				},
			}

			data, err := json.Marshal(entries)
			Expect(err).NotTo(HaveOccurred())

			wikiDir := filepath.Join(inputDir, "photon.wiki")
			Expect(os.MkdirAll(wikiDir, 0755)).To(Succeed())

			records, err := manager.MergeRecordsFromJSON(data, "4.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(1))
			Expect(records).NotTo(HaveKey(ContainSubstring("BDSA")))
			Expect(records).To(HaveKey(ContainSubstring("CVE-2023-5678")))
		})

		It("should skip entries with empty package", func() {
			entries := []map[string]string{
				{
					"cve_id":         "CVE-2023-9999",
					"pkg":            "",
					"version":        "1.0",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "PHSA-2024-9999",
				},
			}

			data, err := json.Marshal(entries)
			Expect(err).NotTo(HaveOccurred())

			records, err := manager.MergeRecordsFromJSON(data, "4.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(0))
		})

		It("should skip entries with NA or empty version", func() {
			entries := []map[string]string{
				{
					"cve_id":         "CVE-2023-0001",
					"pkg":            "testpkg",
					"version":        "NA",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "PHSA-2024-0001",
				},
				{
					"cve_id":         "CVE-2023-0002",
					"pkg":            "testpkg",
					"version":        "",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "PHSA-2024-0002",
				},
			}

			data, err := json.Marshal(entries)
			Expect(err).NotTo(HaveOccurred())

			records, err := manager.MergeRecordsFromJSON(data, "4.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("mergeRecords with advisory map", func() {
		It("should merge multiple packages for same CVE", func() {
			entries := []map[string]string{
				{
					"cve_id":         "CVE-2023-1234",
					"pkg":            "openssl",
					"version":        "3.0.1",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "PHSA-2024-1234",
				},
				{
					"cve_id":         "CVE-2023-1234",
					"pkg":            "openssl-libs",
					"version":        "3.0.1",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "PHSA-2024-1234",
				},
			}

			data, err := json.Marshal(entries)
			Expect(err).NotTo(HaveOccurred())

			wikiDir := filepath.Join(inputDir, "photon.wiki")
			Expect(os.MkdirAll(wikiDir, 0755)).To(Succeed())

			records, err := manager.MergeRecordsFromJSON(data, "4.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(1))

			for _, record := range records {
				fixedIn := record["fixedIn"].([]map[string]interface{})
				Expect(fixedIn).To(HaveLen(2))
			}
		})

		It("should produce correct namespace in records", func() {
			entries := []map[string]string{
				{
					"cve_id":         "CVE-2023-1234",
					"pkg":            "openssl",
					"version":        "3.0.1",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "PHSA-2024-1234",
				},
			}

			data, err := json.Marshal(entries)
			Expect(err).NotTo(HaveOccurred())

			wikiDir := filepath.Join(inputDir, "photon.wiki")
			Expect(os.MkdirAll(wikiDir, 0755)).To(Succeed())

			records, err := manager.MergeRecordsFromJSON(data, "4.0")
			Expect(err).NotTo(HaveOccurred())

			for _, record := range records {
				Expect(record["namespace"]).To(Equal("photon:4.0"))
				Expect(record["severity"]).To(Equal("Unknown"))
			}
		})

		It("should include NVD link", func() {
			entries := []map[string]string{
				{
					"cve_id":         "CVE-2023-1234",
					"pkg":            "openssl",
					"version":        "3.0.1",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "PHSA-2024-1234",
				},
			}

			data, err := json.Marshal(entries)
			Expect(err).NotTo(HaveOccurred())

			records, err := manager.MergeRecordsFromJSON(data, "4.0")
			Expect(err).NotTo(HaveOccurred())

			for _, record := range records {
				Expect(record["link"]).To(ContainSubstring("nvd.nist.gov"))
				Expect(record["link"]).To(ContainSubstring("CVE-2023-1234"))
			}
		})
	})

	Context("parseAdvisoryMap", func() {
		It("should parse wiki markdown files", func() {
			wikiDir := filepath.Join(inputDir, "photon.wiki")
			Expect(os.MkdirAll(wikiDir, 0755)).To(Succeed())

			wikiContent := `# Security Updates 4.0-500

Advisory ID: PHSA-2024-4.0-0500

Issue date: 2024-01-15

## Packages
- openssl CVE-2024-0001
- curl CVE-2024-0002
`
			Expect(os.WriteFile(filepath.Join(wikiDir, "Security-Update-4.0-500.md"), []byte(wikiContent), 0644)).To(Succeed())

			advisoryMap := manager.ParseAdvisoryMap(wikiDir)
			Expect(advisoryMap).NotTo(BeNil())
			Expect(len(advisoryMap)).To(BeNumerically(">=", 2))
		})

		It("should handle missing wiki directory gracefully", func() {
			advisoryMap := manager.ParseAdvisoryMap("/nonexistent/path")
			Expect(advisoryMap).NotTo(BeNil())
			Expect(len(advisoryMap)).To(Equal(0))
		})

		It("should skip files without advisory ID", func() {
			wikiDir := filepath.Join(inputDir, "photon.wiki")
			Expect(os.MkdirAll(wikiDir, 0755)).To(Succeed())

			wikiContent := `# Some Other File
No advisory here.
`
			Expect(os.WriteFile(filepath.Join(wikiDir, "Other-File.md"), []byte(wikiContent), 0644)).To(Succeed())

			advisoryMap := manager.ParseAdvisoryMap(wikiDir)
			Expect(len(advisoryMap)).To(Equal(0))
		})

		It("should pick earliest date for duplicate CVEs", func() {
			wikiDir := filepath.Join(inputDir, "photon.wiki")
			Expect(os.MkdirAll(wikiDir, 0755)).To(Succeed())

			content1 := `Advisory ID: PHSA-2024-4.0-0001
Issue date: 2024-01-10
CVE-2024-0001 fixed in openssl
`
			content2 := `Advisory ID: PHSA-2024-4.0-0002
Issue date: 2024-01-05
CVE-2024-0001 fixed in openssl-libs
`
			Expect(os.WriteFile(filepath.Join(wikiDir, "Security-Update-4.0-001.md"), []byte(content1), 0644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(wikiDir, "Security-Update-4.0-002.md"), []byte(content2), 0644)).To(Succeed())

			advisoryMap := manager.ParseAdvisoryMap(wikiDir)

			key := "4.0:CVE-2024-0001"
			info, ok := advisoryMap[key]
			Expect(ok).To(BeTrue())
			Expect(info.Date).To(Equal("2024-01-05"))
			Expect(info.AdvisoryID).To(Equal("PHSA-2024-4.0-0002"))
		})
	})

	Context("mergeRecords with advisory enrichment", func() {
		It("should include advisory info in metadata when available", func() {
			entries := []map[string]string{
				{
					"cve_id":         "CVE-2024-0001",
					"pkg":            "openssl",
					"version":        "3.0.1",
					"release":        "1.ph4",
					"photon_version": "4.0",
					"advisory":       "PHSA-2024-4.0-0500",
				},
			}

			data, err := json.Marshal(entries)
			Expect(err).NotTo(HaveOccurred())

			wikiDir := filepath.Join(inputDir, "photon.wiki")
			Expect(os.MkdirAll(wikiDir, 0755)).To(Succeed())

			wikiContent := `Advisory ID: PHSA-2024-4.0-0500
Issue date: 2024-01-15
CVE-2024-0001 fixed.
`
			Expect(os.WriteFile(filepath.Join(wikiDir, "Security-Update-4.0-500.md"), []byte(wikiContent), 0644)).To(Succeed())

			manager.SetAdvisoryMap(manager.ParseAdvisoryMap(wikiDir))

			records, err := manager.MergeRecordsFromJSON(data, "4.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(1))

			for _, record := range records {
				metadata := record["metadata"].(map[string]interface{})
				Expect(metadata["issued"]).To(Equal("2024-01-15"))
				Expect(metadata["vendorAdvisory"]).NotTo(BeNil())
			}
		})
	})

	Context("when handling empty input", func() {
		It("should return empty map for empty JSON array", func() {
			data := []byte("[]")

			records, err := manager.MergeRecordsFromJSON(data, "4.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("URLs method", func() {
		It("should return wiki URL", func() {
			urls := manager.URLs()
			Expect(urls).To(BeEmpty())
		})
	})
})
