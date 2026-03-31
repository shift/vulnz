package rhel_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/rhel"
)

var sampleCSAFDoc = `{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "title": "Red Hat Security Advisory: openssl security update",
    "publisher": {
      "name": "Red Hat Product Security",
      "category": "vendor"
    },
    "tracking": {
      "id": "RHSA-2024:1234",
      "status": "final",
      "version": "1",
      "current_release_date": "2024-03-15T12:00:00Z",
      "initial_release_date": "2024-03-15T12:00:00Z"
    },
    "notes": [
      {
        "category": "summary",
        "text": "OpenSSL security update for RHEL 8 and RHEL 9"
      }
    ],
    "aggregate_severity": {
      "text": "Critical"
    }
  },
  "product_tree": {
    "branches": [
      {
        "category": "vendor",
        "name": "Red Hat",
        "branches": [
          {
            "category": "product_name",
            "name": "Red Hat Enterprise Linux 8",
            "product": {
              "product_id": "RHEL-8",
              "product_identification_helper": {
                "cpe": "cpe:/o:redhat:enterprise_linux:8"
              }
            },
            "branches": [
              {
                "category": "product_version",
                "name": "openssl-1.1.1k-9.el8_6",
                "product": {
                  "product_id": "openssl-0:1.1.1k-9.el8_6",
                  "product_identification_helper": {
                    "purl": "pkg:rpm/redhat/openssl@1.1.1k-9.el8_6?epoch=0"
                  }
                }
              }
            ]
          },
          {
            "category": "product_name",
            "name": "Red Hat Enterprise Linux 9",
            "product": {
              "product_id": "RHEL-9",
              "product_identification_helper": {
                "cpe": "cpe:/o:redhat:enterprise_linux:9"
              }
            },
            "branches": [
              {
                "category": "product_version",
                "name": "openssl-3.0.7-18.el9",
                "product": {
                  "product_id": "openssl-0:3.0.7-18.el9",
                  "product_identification_helper": {
                    "purl": "pkg:rpm/redhat/openssl@3.0.7-18.el9?epoch=0"
                  }
                }
              }
            ]
          }
        ]
      }
    ],
    "full_product_names": [
      {
        "product_id": "AppStream-8.8.0.Z.MAIN.EUS:openssl-0:1.1.1k-9.el8_6.src.rpm",
        "name": "Red Hat Enterprise Linux 8 - AppStream 8.8.0.Z.MAIN.EUS: openssl-0:1.1.1k-9.el8_6.src.rpm"
      },
      {
        "product_id": "AppStream-9.2.0.Z:openssl-0:3.0.7-18.el9.src.rpm",
        "name": "Red Hat Enterprise Linux 9 - AppStream 9.2.0.Z: openssl-0:3.0.7-18.el9.src.rpm"
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2024-0001",
      "title": "OpenSSL buffer overflow",
      "remediations": [
        {
          "category": "vendor_fix",
          "details": "Upgrade openssl to 1.1.1k-9.el8_6 for RHEL 8 or 3.0.7-18.el9 for RHEL 9",
          "url": "https://access.redhat.com/errata/RHSA-2024:1234",
          "product_ids": [
            "AppStream-8.8.0.Z.MAIN.EUS:openssl-0:1.1.1k-9.el8_6.src.rpm",
            "AppStream-9.2.0.Z:openssl-0:3.0.7-18.el9.src.rpm"
          ]
        }
      ],
      "scores": [
        {
          "cvss_v3": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL"
          },
          "products": ["AppStream-8.8.0.Z.MAIN.EUS:openssl-0:1.1.1k-9.el8_6.src.rpm"]
        }
      ],
      "threats": [
        {
          "category": "impact",
          "details": "Critical"
        }
      ]
    },
    {
      "cve": "CVE-2024-0002",
      "title": "OpenSSL timing attack",
      "remediations": [
        {
          "category": "vendor_fix",
          "details": "Upgrade openssl to fix timing attack",
          "url": "https://access.redhat.com/errata/RHSA-2024:1234",
          "product_ids": [
            "AppStream-8.8.0.Z.MAIN.EUS:openssl-0:1.1.1k-9.el8_6.src.rpm"
          ]
        }
      ],
      "scores": [
        {
          "cvss_v3": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            "baseScore": 5.4,
            "baseSeverity": "MEDIUM"
          },
          "products": ["AppStream-8.8.0.Z.MAIN.EUS:openssl-0:1.1.1k-9.el8_6.src.rpm"]
        }
      ]
    }
  ]
}`

var sampleCSAFDocMultiModule = `{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "title": "Red Hat Security Advisory: ruby security update",
    "publisher": {
      "name": "Red Hat Product Security",
      "category": "vendor"
    },
    "tracking": {
      "id": "RHSA-2024:5678",
      "status": "final",
      "version": "1",
      "current_release_date": "2024-04-01T10:00:00Z",
      "initial_release_date": "2024-04-01T10:00:00Z"
    },
    "notes": [
      {
        "category": "summary",
        "text": "Ruby module security update for RHEL 8"
      }
    ],
    "aggregate_severity": {
      "text": "Important"
    }
  },
  "product_tree": {
    "branches": [
      {
        "category": "vendor",
        "name": "Red Hat",
        "branches": [
          {
            "category": "product_name",
            "name": "Red Hat Enterprise Linux 8",
            "product": {
              "product_id": "RHEL-8",
              "product_identification_helper": {
                "cpe": "cpe:/o:redhat:enterprise_linux:8"
              }
            },
            "branches": [
              {
                "category": "product_version",
                "name": "ruby-3.1.2-170.el8",
                "product": {
                  "product_id": "ruby-0:3.1.2-170.el8",
                  "product_identification_helper": {
                    "purl": "pkg:rpm/redhat/ruby@3.1.2-170.el8?epoch=0&rpmmod=ruby:3.1:8090020240311122605"
                  }
                }
              }
            ]
          }
        ]
      }
    ],
    "full_product_names": [
      {
        "product_id": "AppStream-8.8.0.Z:ruby-0:3.1.2-170.el8.src.rpm",
        "name": "Red Hat Enterprise Linux 8 - AppStream 8.8.0.Z: ruby-0:3.1.2-170.el8.src.rpm"
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2024-0099",
      "remediations": [
        {
          "category": "vendor_fix",
          "details": "Upgrade ruby module",
          "url": "https://access.redhat.com/errata/RHSA-2024:5678",
          "product_ids": ["AppStream-8.8.0.Z:ruby-0:3.1.2-170.el8.src.rpm"]
        }
      ]
    }
  ]
}`

var _ = Describe("RHEL Manager", func() {
	var (
		tempDir string
		logger  *slog.Logger
		config  provider.Config
		manager *rhel.Manager
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "rhel-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))

		config = provider.Config{
			Name:      "rhel",
			Workspace: tempDir,
			Storage: provider.StorageConfig{
				Type: "flat-file",
				Path: tempDir + "/storage",
			},
			HTTP:   provider.DefaultHTTPConfig(),
			Logger: logger,
		}

		manager = rhel.NewManager(config)
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("CSAF document parsing", func() {
		It("should parse a valid CSAF document and extract vulnerabilities", func() {
			advisoriesBasePath := filepath.Join(tempDir, "advisories")
			advisoriesPath := filepath.Join(advisoriesBasePath, "2024")
			Expect(os.MkdirAll(advisoriesPath, 0755)).To(Succeed())

			err := os.WriteFile(filepath.Join(advisoriesPath, "rhsa-2024_1234.json"), []byte(sampleCSAFDoc), 0644)
			Expect(err).NotTo(HaveOccurred())

			downloader := rhel.NewCSAFDownloader(advisoriesBasePath, tempDir, http.DefaultClient, "vulnz-go/1.0")
			records, err := downloader.ParseDirectory(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeEmpty())

			var foundCVE0001, foundCVE0002 bool
			for _, rec := range records {
				for _, cve := range rec.CVEs {
					switch cve {
					case "CVE-2024-0001":
						foundCVE0001 = true
						Expect(rec.Severity).To(Equal("Critical"))
						Expect(rec.AdvisoryURL).To(ContainSubstring("RHSA-2024:1234"))
						Expect(rec.Description).To(ContainSubstring("OpenSSL"))
					case "CVE-2024-0002":
						foundCVE0002 = true
						Expect(rec.Severity).To(Equal("Critical"))
					}
				}
			}
			Expect(foundCVE0001).To(BeTrue())
			Expect(foundCVE0002).To(BeTrue())
		})

		It("should extract CVSS scores from CSAF documents", func() {
			advisoriesBasePath := filepath.Join(tempDir, "advisories")
			advisoriesPath := filepath.Join(advisoriesBasePath, "2024")
			Expect(os.MkdirAll(advisoriesPath, 0755)).To(Succeed())

			err := os.WriteFile(filepath.Join(advisoriesPath, "rhsa-2024_1234.json"), []byte(sampleCSAFDoc), 0644)
			Expect(err).NotTo(HaveOccurred())

			downloader := rhel.NewCSAFDownloader(advisoriesBasePath, tempDir, http.DefaultClient, "vulnz-go/1.0")
			records, err := downloader.ParseDirectory(context.Background())
			Expect(err).NotTo(HaveOccurred())

			var cve0001Record *rhel.CSAFRecord
			for i := range records {
				for _, cve := range records[i].CVEs {
					if cve == "CVE-2024-0001" {
						cve0001Record = &records[i]
						break
					}
				}
				if cve0001Record != nil {
					break
				}
			}
			Expect(cve0001Record).NotTo(BeNil())
			Expect(cve0001Record.CVSS).NotTo(BeEmpty())
			Expect(cve0001Record.CVSS[0].Version).To(Equal("3.1"))
			Expect(cve0001Record.CVSS[0].VectorString).To(ContainSubstring("CVSS:3.1"))
		})

		It("should resolve namespaces from CPEs", func() {
			advisoriesBasePath := filepath.Join(tempDir, "advisories")
			advisoriesPath := filepath.Join(advisoriesBasePath, "2024")
			Expect(os.MkdirAll(advisoriesPath, 0755)).To(Succeed())

			err := os.WriteFile(filepath.Join(advisoriesPath, "rhsa-2024_1234.json"), []byte(sampleCSAFDoc), 0644)
			Expect(err).NotTo(HaveOccurred())

			downloader := rhel.NewCSAFDownloader(advisoriesBasePath, tempDir, http.DefaultClient, "vulnz-go/1.0")
			records, err := downloader.ParseDirectory(context.Background())
			Expect(err).NotTo(HaveOccurred())

			namespaces := make(map[string]bool)
			for _, rec := range records {
				for _, fix := range rec.FixedIn {
					namespaces[fix.Namespace] = true
				}
			}
			Expect(namespaces["rhel:8"]).To(BeTrue())
		})

		It("should handle empty advisories directory gracefully", func() {
			advisoriesPath := filepath.Join(tempDir, "advisories")
			Expect(os.MkdirAll(advisoriesPath, 0755)).To(Succeed())

			downloader := rhel.NewCSAFDownloader(advisoriesPath, tempDir, http.DefaultClient, "vulnz-go/1.0")
			records, err := downloader.ParseDirectory(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(BeEmpty())
		})

		It("should handle malformed CSAF documents gracefully", func() {
			advisoriesBasePath := filepath.Join(tempDir, "advisories")
			advisoriesPath := filepath.Join(advisoriesBasePath, "2024")
			Expect(os.MkdirAll(advisoriesPath, 0755)).To(Succeed())

			err := os.WriteFile(filepath.Join(advisoriesPath, "bad.json"), []byte("{invalid json}"), 0644)
			Expect(err).NotTo(HaveOccurred())

			downloader := rhel.NewCSAFDownloader(advisoriesBasePath, tempDir, http.DefaultClient, "vulnz-go/1.0")
			records, err := downloader.ParseDirectory(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(BeEmpty())
		})

		It("should handle CSAF documents with no vulnerabilities", func() {
			advisoriesBasePath := filepath.Join(tempDir, "advisories")
			advisoriesPath := filepath.Join(advisoriesBasePath, "2024")
			Expect(os.MkdirAll(advisoriesPath, 0755)).To(Succeed())

			noVulnDoc := `{
				"document": {
					"category": "csaf_security_advisory",
					"csaf_version": "2.0",
					"title": "No vulns advisory",
					"publisher": {"name": "Red Hat", "category": "vendor"},
					"tracking": {"id": "RHSA-2024:9999", "status": "final", "version": "1"}
				},
				"vulnerabilities": []
			}`
			err := os.WriteFile(filepath.Join(advisoriesPath, "rhsa-2024_9999.json"), []byte(noVulnDoc), 0644)
			Expect(err).NotTo(HaveOccurred())

			downloader := rhel.NewCSAFDownloader(advisoriesBasePath, tempDir, http.DefaultClient, "vulnz-go/1.0")
			records, err := downloader.ParseDirectory(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(BeEmpty())
		})
	})

	Context("platform resolution", func() {
		It("should parse RHEL version from product name", func() {
			Expect(rhel.ParsePlatformFromProductName("Red Hat Enterprise Linux 8")).To(Equal("8"))
			Expect(rhel.ParsePlatformFromProductName("Red Hat Enterprise Linux 9")).To(Equal("9"))
			Expect(rhel.ParsePlatformFromProductName("Red Hat Enterprise Linux 7")).To(Equal("7"))
		})

		It("should parse EUS product names", func() {
			Expect(rhel.ParsePlatformFromProductName("Red Hat Enterprise Linux 8.6 Extended Update Support")).To(Equal("8.6"))
		})

		It("should parse ELS product names", func() {
			Expect(rhel.ParsePlatformFromProductName("Red Hat Enterprise Linux 6 Extended Lifecycle Support")).To(Equal("6"))
		})

		It("should return empty for non-RHEL product names", func() {
			Expect(rhel.ParsePlatformFromProductName("Ubuntu 22.04")).To(BeEmpty())
			Expect(rhel.ParsePlatformFromProductName("")).To(BeEmpty())
		})
	})

	Context("severity normalization", func() {
		It("should normalize RHEL severity values", func() {
			Expect(rhel.NormalizeSeverity("Critical")).To(Equal("Critical"))
			Expect(rhel.NormalizeSeverity("critical")).To(Equal("Critical"))
			Expect(rhel.NormalizeSeverity("Important")).To(Equal("High"))
			Expect(rhel.NormalizeSeverity("Moderate")).To(Equal("Medium"))
			Expect(rhel.NormalizeSeverity("Low")).To(Equal("Low"))
			Expect(rhel.NormalizeSeverity("")).To(Equal("Unknown"))
			Expect(rhel.NormalizeSeverity("weird")).To(Equal("Unknown"))
		})
	})

	Context("incremental sync with mock server", func() {
		var ts *httptest.Server

		BeforeEach(func() {
			ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "archive_latest.txt"):
					w.Write([]byte("csaf_advisories_2024-03-15.tar.zst"))
				case strings.HasSuffix(r.URL.Path, "changes.csv"):
					w.Write([]byte(`"2024/rhsa-2024_1234.json","2024-03-16T12:00:00+00:00"
`))
				case strings.HasSuffix(r.URL.Path, "deletions.csv"):
					w.Write([]byte("\n"))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
		})

		AfterEach(func() {
			ts.Close()
		})

		It("should track URLs from downloads", func() {
			urls := manager.URLs()
			Expect(urls).To(BeEmpty())
		})
	})
})

var _ = Describe("CSAF Downloader", func() {
	var tempDir string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "rhel-csaf-test-*")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("CSAF record parsing", func() {
		It("should parse CSAF records to vulnerability records", func() {
			advisoriesBasePath := filepath.Join(tempDir, "advisories")
			advisoriesPath := filepath.Join(advisoriesBasePath, "2024")
			Expect(os.MkdirAll(advisoriesPath, 0755)).To(Succeed())

			err := os.WriteFile(filepath.Join(advisoriesPath, "rhsa-2024_1234.json"), []byte(sampleCSAFDoc), 0644)
			Expect(err).NotTo(HaveOccurred())

			downloader := rhel.NewCSAFDownloader(
				advisoriesBasePath,
				tempDir,
				http.DefaultClient,
				"vulnz-go/1.0",
			)

			records, err := downloader.ParseDirectory(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeEmpty())

			vulns := rhel.RecordsToVulnerabilities(records)
			Expect(vulns).NotTo(BeEmpty())

			for _, vuln := range vulns {
				Expect(vuln.Name).To(Or(Equal("CVE-2024-0001"), Equal("CVE-2024-0002")))
				Expect(vuln.Severity).NotTo(BeEmpty())
				Expect(vuln.Metadata).NotTo(BeNil())
			}
		})
	})
})

var _ = Describe("CSAF document structure validation", func() {
	It("should produce valid CSAF JSON that can be loaded by gocsaf", func() {
		var doc csaf.Advisory
		err := json.Unmarshal([]byte(sampleCSAFDoc), &doc)
		Expect(err).NotTo(HaveOccurred())

		Expect(doc.Document).NotTo(BeNil())
		Expect(doc.Document.Tracking).NotTo(BeNil())
		Expect(string(*doc.Document.Tracking.ID)).To(Equal("RHSA-2024:1234"))
		Expect(doc.Vulnerabilities).NotTo(BeEmpty())
		Expect(len(doc.Vulnerabilities)).To(BeNumerically(">=", 2))
	})

	It("should extract CVEs correctly from CSAF document", func() {
		var doc csaf.Advisory
		err := json.Unmarshal([]byte(sampleCSAFDoc), &doc)
		Expect(err).NotTo(HaveOccurred())

		var cves []string
		for _, vuln := range doc.Vulnerabilities {
			if vuln.CVE != nil {
				cves = append(cves, string(*vuln.CVE))
			}
		}
		Expect(cves).To(ContainElements("CVE-2024-0001", "CVE-2024-0002"))
	})

	It("should handle multi-CVE CSAF documents", func() {
		var doc csaf.Advisory
		err := json.Unmarshal([]byte(sampleCSAFDoc), &doc)
		Expect(err).NotTo(HaveOccurred())

		Expect(len(doc.Vulnerabilities)).To(BeNumerically(">=", 2))

		for _, vuln := range doc.Vulnerabilities {
			Expect(vuln.CVE).NotTo(BeNil())
			Expect(string(*vuln.CVE)).To(HavePrefix("CVE-"))
		}
	})

	It("should extract remediation product IDs", func() {
		var doc csaf.Advisory
		err := json.Unmarshal([]byte(sampleCSAFDoc), &doc)
		Expect(err).NotTo(HaveOccurred())

		for _, vuln := range doc.Vulnerabilities {
			if vuln.Remediations != nil {
				for _, rem := range vuln.Remediations {
					if rem.Category != nil && string(*rem.Category) == "vendor_fix" {
						Expect(rem.ProductIds).NotTo(BeNil())
						Expect(len(*rem.ProductIds)).To(BeNumerically(">=", 1))
					}
				}
			}
		}
	})

	It("should extract CVSS v3 scores", func() {
		var doc csaf.Advisory
		err := json.Unmarshal([]byte(sampleCSAFDoc), &doc)
		Expect(err).NotTo(HaveOccurred())

		for _, vuln := range doc.Vulnerabilities {
			if vuln.Scores != nil {
				for _, score := range vuln.Scores {
					if score.CVSS3 != nil {
						Expect(*score.CVSS3.BaseScore).To(BeNumerically(">", 0))
						Expect(string(*score.CVSS3.VectorString)).To(HavePrefix("CVSS:3.1"))
					}
				}
			}
		}
	})

	It("should extract aggregate severity", func() {
		var doc csaf.Advisory
		err := json.Unmarshal([]byte(sampleCSAFDoc), &doc)
		Expect(err).NotTo(HaveOccurred())

		Expect(doc.Document.AggregateSeverity).NotTo(BeNil())
		Expect(string(*doc.Document.AggregateSeverity.Text)).To(Equal("Critical"))
	})

	It("should extract summary from notes", func() {
		var doc csaf.Advisory
		err := json.Unmarshal([]byte(sampleCSAFDoc), &doc)
		Expect(err).NotTo(HaveOccurred())

		Expect(doc.Document.Notes).NotTo(BeEmpty())
		foundSummary := false
		for _, note := range doc.Document.Notes {
			if note.NoteCategory != nil && string(*note.NoteCategory) == "summary" {
				foundSummary = true
				Expect(*note.Text).To(ContainSubstring("OpenSSL"))
			}
		}
		Expect(foundSummary).To(BeTrue())
	})

	It("should extract product tree CPEs", func() {
		var doc csaf.Advisory
		err := json.Unmarshal([]byte(sampleCSAFDoc), &doc)
		Expect(err).NotTo(HaveOccurred())

		Expect(doc.ProductTree).NotTo(BeNil())
		Expect(doc.ProductTree.Branches).NotTo(BeEmpty())
	})
})

var _ = Describe("RHEL CSAF end-to-end with mock filesystem", func() {
	var tempDir string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "rhel-e2e-test-*")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	It("should parse multiple CSAF advisories and deduplicate CVEs", func() {
		advisoriesBasePath := filepath.Join(tempDir, "advisories")
		advisoriesPath := filepath.Join(advisoriesBasePath, "2024")
		Expect(os.MkdirAll(advisoriesPath, 0755)).To(Succeed())

		for i, name := range []string{"rhsa-2024_1234.json", "rhsa-2024_5678.json"} {
			content := sampleCSAFDoc
			if i == 1 {
				content = sampleCSAFDocMultiModule
			}
			err := os.WriteFile(filepath.Join(advisoriesPath, name), []byte(content), 0644)
			Expect(err).NotTo(HaveOccurred())
		}

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
		config := provider.Config{
			Name:      "rhel",
			Workspace: tempDir,
			Storage:   provider.StorageConfig{Type: "flat-file", Path: tempDir + "/storage"},
			HTTP:      provider.DefaultHTTPConfig(),
			Logger:    logger,
		}

		manager := rhel.NewManager(config)

		downloader := rhel.NewCSAFDownloader(
			filepath.Join(tempDir, "advisories"),
			tempDir,
			http.DefaultClient,
			"vulnz-go/1.0",
		)

		records, err := downloader.ParseDirectory(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(records).NotTo(BeEmpty())

		cveSet := make(map[string]bool)
		for _, rec := range records {
			cveSet[rec.AdvisoryID] = true
			for _, cve := range rec.CVEs {
				cveSet[cve] = true
			}
		}
		Expect(cveSet).To(HaveKey("CVE-2024-0001"))
		Expect(cveSet).To(HaveKey("CVE-2024-0002"))
		Expect(cveSet).To(HaveKey("CVE-2024-0099"))

		_ = manager
	})

	It("should produce well-formed vulnerability payloads", func() {
		advisoriesBasePath := filepath.Join(tempDir, "advisories")
		advisoriesPath := filepath.Join(advisoriesBasePath, "2024")
		Expect(os.MkdirAll(advisoriesPath, 0755)).To(Succeed())

		err := os.WriteFile(filepath.Join(advisoriesPath, "rhsa-2024_1234.json"), []byte(sampleCSAFDoc), 0644)
		Expect(err).NotTo(HaveOccurred())

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
		config := provider.Config{
			Name:      "rhel",
			Workspace: tempDir,
			Storage:   provider.StorageConfig{Type: "flat-file", Path: tempDir + "/storage"},
			HTTP:      provider.DefaultHTTPConfig(),
			Logger:    logger,
		}

		_ = rhel.NewManager(config)

		downloader := rhel.NewCSAFDownloader(
			filepath.Join(tempDir, "advisories"),
			tempDir,
			http.DefaultClient,
			"vulnz-go/1.0",
		)

		records, err := downloader.ParseDirectory(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(records).NotTo(BeEmpty())

		vulns := rhel.RecordsToVulnerabilities(records)
		Expect(vulns).NotTo(BeEmpty())

		for _, rec := range vulns {
			Expect(rec.Name).NotTo(BeEmpty())
			Expect(rec.NamespaceName).NotTo(BeEmpty())
			Expect(rec.Severity).NotTo(BeEmpty())
			Expect(rec.Link).NotTo(BeEmpty())
			Expect(rec.FixedIn).NotTo(BeEmpty())
			Expect(rec.CVSS).NotTo(BeEmpty())
			Expect(rec.Metadata).NotTo(BeNil())

			payload := rec.ToPayload()
			Expect(payload).To(HaveKey("Vulnerability"))

			data, err := json.Marshal(payload)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(ContainSubstring(rec.Name))
		}
	})
})
