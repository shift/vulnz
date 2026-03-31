package fedora_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/fedora"
)

var _ = Describe("Fedora Manager", func() {
	var (
		manager    *fedora.Manager
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "fedora-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "fedora",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}
	})

	AfterEach(func() {
		if testServer != nil {
			testServer.Close()
		}
		os.RemoveAll(tempDir)
	})

	Context("when fetching paginated Bodhi data", func() {
		BeforeEach(func() {
			pageCount := 0
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pageParam := r.URL.Query().Get("page")
				page, _ := strconv.Atoi(pageParam)
				if page == 0 {
					page = 1
				}
				pageCount++

				w.Header().Set("Content-Type", "application/json")

				if page == 1 {
					resp := map[string]interface{}{
						"pages": 2,
						"updates": []interface{}{
							map[string]interface{}{
								"alias":    "FEDORA-2025-abc123",
								"title":    "CVE-2025-1234 important security update",
								"released": "2025-01-15 12:00:00",
								"status":   "stable",
								"type":     "security",
								"severity": "important",
								"notes":    "Fix for CVE-2025-1234",
								"url":      "https://bodhi.fedoraproject.org/updates/FEDORA-2025-abc123",
								"builds": []interface{}{
									map[string]interface{}{
										"nvr":   "bash-5.2-10.fc41",
										"epoch": 0,
										"type":  "rpm",
									},
								},
								"bugs": []interface{}{
									map[string]interface{}{
										"bug_id":   12345,
										"title":    "CVE-2025-1234 important: bash arbitrary command execution",
										"security": true,
									},
								},
								"release": map[string]interface{}{
									"version": "41",
								},
							},
							map[string]interface{}{
								"alias":    "FEDORA-2025-def456",
								"title":    "CVE-2025-5678 CVE-2025-9012 critical security update",
								"released": "2025-02-20 08:00:00",
								"status":   "stable",
								"type":     "security",
								"severity": "critical",
								"notes":    "Fix for multiple CVEs",
								"url":      "https://bodhi.fedoraproject.org/updates/FEDORA-2025-def456",
								"builds": []interface{}{
									map[string]interface{}{
										"nvr":   "openssl-3.2-5.fc42",
										"epoch": 1,
										"type":  "rpm",
									},
								},
								"bugs": []interface{}{
									map[string]interface{}{
										"bug_id":   23456,
										"title":    "CVE-2025-5678 critical: openssl buffer overflow",
										"security": true,
									},
									map[string]interface{}{
										"bug_id":   23457,
										"title":    "CVE-2025-9012 critical: openssl DoS",
										"security": true,
									},
								},
								"release": map[string]interface{}{
									"version": "42",
								},
							},
						},
					}
					json.NewEncoder(w).Encode(resp)
				} else {
					resp := map[string]interface{}{
						"pages":   2,
						"updates": []interface{}{},
					}
					json.NewEncoder(w).Encode(resp)
				}
			}))

			manager = fedora.NewManagerWithURL(testServer.URL, config)
		})

		It("should fetch all pages and return records", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(3))
		})

		It("should extract CVEs from bug titles", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(HaveKey("fedora:41/CVE-2025-1234"))
			Expect(records).To(HaveKey("fedora:42/CVE-2025-5678"))
			Expect(records).To(HaveKey("fedora:42/CVE-2025-9012"))
		})

		It("should set correct severity from bug title", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			record := records["fedora:41/CVE-2025-1234"]
			vuln := record["Vulnerability"].(map[string]interface{})
			Expect(vuln["Severity"]).To(Equal("High"))
		})

		It("should parse NVR into correct fixedIn entries", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			record := records["fedora:41/CVE-2025-1234"]
			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]interface{})
			Expect(fixedIn).To(HaveLen(1))

			entry := fixedIn[0].(map[string]interface{})
			Expect(entry["Name"]).To(Equal("bash"))
			Expect(entry["Version"]).To(Equal("0:5.2-10.fc41"))
			Expect(entry["VersionFormat"]).To(Equal("rpm"))
			Expect(entry["NamespaceName"]).To(Equal("fedora:41"))
		})

		It("should handle epoch in version", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			record := records["fedora:42/CVE-2025-5678"]
			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]interface{})
			Expect(fixedIn).To(HaveLen(1))

			entry := fixedIn[0].(map[string]interface{})
			Expect(entry["Name"]).To(Equal("openssl"))
			Expect(entry["Version"]).To(Equal("1:3.2-5.fc42"))
		})

		It("should include CVE references in metadata", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			record := records["fedora:41/CVE-2025-1234"]
			vuln := record["Vulnerability"].(map[string]interface{})
			metadata := vuln["Metadata"].(map[string]interface{})
			cveRefs := metadata["CVE"].([]interface{})
			Expect(cveRefs).To(HaveLen(1))

			cveRef := cveRefs[0].(map[string]interface{})
			Expect(cveRef["Name"]).To(Equal("CVE-2025-1234"))
			Expect(cveRef["Link"]).To(Equal("https://nvd.nist.gov/vuln/detail/CVE-2025-1234"))
		})

		It("should include issued and updated in metadata", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			record := records["fedora:41/CVE-2025-1234"]
			vuln := record["Vulnerability"].(map[string]interface{})
			metadata := vuln["Metadata"].(map[string]interface{})
			Expect(metadata["Issued"]).To(Equal("2025-01-15 12:00:00"))
			Expect(metadata["Updated"]).To(Equal("2025-01-15 12:00:00"))
		})

		It("should include vendor advisory in fixedIn", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			record := records["fedora:41/CVE-2025-1234"]
			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]interface{})
			entry := fixedIn[0].(map[string]interface{})
			va := entry["VendorAdvisory"].(map[string]interface{})
			Expect(va["NoAdvisory"]).To(BeFalse())
			summary := va["AdvisorySummary"].([]interface{})
			Expect(summary).To(HaveLen(1))
			adv := summary[0].(map[string]interface{})
			Expect(adv["ID"]).To(Equal("FEDORA-2025-abc123"))
		})

		It("should track all fetched URLs", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			urls := manager.URLs()
			Expect(len(urls)).To(Equal(2))
		})
	})

	Context("when merging CVEs across updates", func() {
		BeforeEach(func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				resp := map[string]interface{}{
					"pages": 1,
					"updates": []interface{}{
						map[string]interface{}{
							"alias":    "FEDORA-2025-merge1",
							"title":    "CVE-2025-1111 fix",
							"released": "2025-03-01 00:00:00",
							"status":   "stable",
							"type":     "security",
							"severity": "moderate",
							"builds": []interface{}{
								map[string]interface{}{
									"nvr":   "pkg1-1.0-1.fc40",
									"epoch": 0,
									"type":  "rpm",
								},
							},
							"bugs": []interface{}{
								map[string]interface{}{
									"bug_id":   11111,
									"title":    "CVE-2025-1111 moderate: pkg1 issue",
									"security": true,
								},
							},
							"release": map[string]interface{}{
								"version": "40",
							},
						},
						map[string]interface{}{
							"alias":    "FEDORA-2025-merge2",
							"title":    "CVE-2025-1111 additional fix",
							"released": "2025-03-15 00:00:00",
							"status":   "stable",
							"type":     "security",
							"severity": "moderate",
							"builds": []interface{}{
								map[string]interface{}{
									"nvr":   "pkg2-2.0-1.fc40",
									"epoch": 0,
									"type":  "rpm",
								},
							},
							"bugs": []interface{}{
								map[string]interface{}{
									"bug_id":   22222,
									"title":    "CVE-2025-1111 moderate: pkg2 issue",
									"security": true,
								},
							},
							"release": map[string]interface{}{
								"version": "40",
							},
						},
					},
				}
				json.NewEncoder(w).Encode(resp)
			}))

			manager = fedora.NewManagerWithURL(testServer.URL, config)
		})

		It("should merge FixedIn entries for same CVE from different updates", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(1))

			record := records["fedora:40/CVE-2025-1111"]
			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]interface{})
			Expect(fixedIn).To(HaveLen(2))

			names := make(map[string]bool)
			for _, fi := range fixedIn {
				entry := fi.(map[string]interface{})
				names[entry["Name"].(string)] = true
			}
			Expect(names).To(HaveKey("pkg1"))
			Expect(names).To(HaveKey("pkg2"))
		})
	})

	Context("when update has no security bugs", func() {
		BeforeEach(func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				resp := map[string]interface{}{
					"pages": 1,
					"updates": []interface{}{
						map[string]interface{}{
							"alias":    "FEDORA-2025-nocve",
							"title":    "CVE-2025-9999 security update",
							"released": "2025-01-01 00:00:00",
							"status":   "stable",
							"type":     "security",
							"severity": "low",
							"builds": []interface{}{
								map[string]interface{}{
									"nvr":   "testpkg-1.0-1.fc39",
									"epoch": 0,
									"type":  "rpm",
								},
							},
							"bugs": []interface{}{
								map[string]interface{}{
									"bug_id":   99999,
									"title":    "not a security bug",
									"security": false,
								},
							},
							"release": map[string]interface{}{
								"version": "39",
							},
						},
					},
				}
				json.NewEncoder(w).Encode(resp)
			}))

			manager = fedora.NewManagerWithURL(testServer.URL, config)
		})

		It("should fall back to extracting CVE from title", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(HaveKey("fedora:39/CVE-2025-9999"))
		})
	})

	Context("when handling HTTP errors", func() {
		BeforeEach(func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			manager = fedora.NewManagerWithURL(testServer.URL, config)
		})

		It("should return error on HTTP failure", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code"))
		})
	})

	Context("when handling malformed data", func() {
		BeforeEach(func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"invalid": json`))
			}))
			manager = fedora.NewManagerWithURL(testServer.URL, config)
		})

		It("should return error on invalid JSON", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse JSON"))
		})
	})

	Context("when handling empty results", func() {
		BeforeEach(func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"pages": 1, "updates": []}`))
			}))
			manager = fedora.NewManagerWithURL(testServer.URL, config)
		})

		It("should return empty map for empty updates", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"pages": 1, "updates": []}`))
			}))
			manager = fedora.NewManagerWithURL(testServer.URL, config)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("URLs method", func() {
		It("should return empty before fetch", func() {
			manager = fedora.NewManagerWithURL(testServer.URL, config)
			urls := manager.URLs()
			Expect(urls).To(BeEmpty())
		})
	})

	Context("NVR parsing", func() {
		It("should parse standard NVR format", func() {
			name, version, release, ok := fedora.TestParseNVR("bash-5.2-10.fc41")
			Expect(ok).To(BeTrue())
			Expect(name).To(Equal("bash"))
			Expect(version).To(Equal("5.2"))
			Expect(release).To(Equal("10.fc41"))
		})

		It("should reject malformed NVR", func() {
			_, _, _, ok := fedora.TestParseNVR("bash-5.2")
			Expect(ok).To(BeFalse())
		})

		It("should reject empty NVR", func() {
			_, _, _, ok := fedora.TestParseNVR("")
			Expect(ok).To(BeFalse())
		})
	})

	Context("CVE extraction", func() {
		It("should extract CVEs from security bug titles", func() {
			cves := fedora.TestExtractCVEs([]map[string]interface{}{
				{"title": "CVE-2025-1234 critical: buffer overflow", "security": true},
				{"title": "CVE-2025-5678 high: DoS", "security": true},
			}, "some title")
			Expect(cves).To(Equal([]string{"CVE-2025-1234", "CVE-2025-5678"}))
		})

		It("should skip non-security bugs", func() {
			cves := fedora.TestExtractCVEs([]map[string]interface{}{
				{"title": "CVE-2025-1234 critical: buffer overflow", "security": false},
			}, "some title")
			Expect(cves).To(BeEmpty())
		})

		It("should deduplicate CVEs", func() {
			cves := fedora.TestExtractCVEs([]map[string]interface{}{
				{"title": "CVE-2025-1234 critical: overflow", "security": true},
				{"title": "CVE-2025-1234 also mentioned here", "security": true},
			}, "some title")
			Expect(cves).To(Equal([]string{"CVE-2025-1234"}))
		})

		It("should fall back to title when no security bugs", func() {
			cves := fedora.TestExtractCVEs([]map[string]interface{}{
				{"title": "not security", "security": false},
			}, "CVE-2025-9999 security update for foo")
			Expect(cves).To(Equal([]string{"CVE-2025-9999"}))
		})
	})

	Context("severity normalization", func() {
		It("should normalize all severity levels", func() {
			Expect(fedora.TestNormalizeSeverity("urgent")).To(Equal("Critical"))
			Expect(fedora.TestNormalizeSeverity("critical")).To(Equal("Critical"))
			Expect(fedora.TestNormalizeSeverity("important")).To(Equal("High"))
			Expect(fedora.TestNormalizeSeverity("high")).To(Equal("High"))
			Expect(fedora.TestNormalizeSeverity("moderate")).To(Equal("Medium"))
			Expect(fedora.TestNormalizeSeverity("medium")).To(Equal("Medium"))
			Expect(fedora.TestNormalizeSeverity("low")).To(Equal("Low"))
			Expect(fedora.TestNormalizeSeverity("none")).To(Equal("Unknown"))
			Expect(fedora.TestNormalizeSeverity("")).To(Equal("Unknown"))
			Expect(fedora.TestNormalizeSeverity("unknown_label")).To(Equal("Unknown"))
		})
	})
})
