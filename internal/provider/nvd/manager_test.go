package nvd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/nvd"
)

func makeNVDResponse(totalResults int, startIndex int, resultsPerPage int, vulns []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"totalResults":    totalResults,
		"startIndex":      startIndex,
		"resultsPerPage":  resultsPerPage,
		"vulnerabilities": vulns,
	}
}

func makeCVE(id string) map[string]interface{} {
	return map[string]interface{}{
		"cve": map[string]interface{}{
			"id": id,
			"descriptions": []interface{}{
				map[string]interface{}{
					"lang":  "en",
					"value": fmt.Sprintf("Test vulnerability %s", id),
				},
			},
			"configurations": []interface{}{
				map[string]interface{}{
					"nodes": []interface{}{
						map[string]interface{}{
							"cpeMatch": []interface{}{
								map[string]interface{}{
									"criteria":   "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*",
									"vulnerable": true,
								},
							},
						},
					},
				},
			},
			"references": []interface{}{
				map[string]interface{}{"url": "https://example.com/" + strings.ToLower(id)},
			},
		},
	}
}

var _ = Describe("NVD Manager", func() {
	var (
		manager    *nvd.Manager
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
		requestLog []string
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "nvd-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		requestLog = nil
		pageCalls := 0

		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestLog = append(requestLog, r.URL.String())

			if r.URL.Path != "/rest/json/cves/2.0" {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "application/json")

			startIndex := 0
			if si := r.URL.Query().Get("startIndex"); si != "" {
				fmt.Sscanf(si, "%d", &startIndex)
			}

			vulns := []map[string]interface{}{
				makeCVE("CVE-2023-1234"),
				makeCVE("CVE-2023-5678"),
				makeCVE("CVE-2024-0001"),
			}

			totalResults := 5
			resultsPerPage := 3

			if startIndex >= 3 {
				vulns = []map[string]interface{}{
					makeCVE("CVE-2024-0002"),
					makeCVE("CVE-2024-0003"),
				}
				pageCalls++
			} else {
				pageCalls++
			}

			resp := makeNVDResponse(totalResults, startIndex, resultsPerPage, vulns)
			data, _ := json.Marshal(resp)
			w.Write(data)
		}))

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "nvd",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = nvd.NewManagerWithAPIURL(config, testServer.URL+"/rest/json/cves/2.0")
		manager.SetRetryWait(10 * time.Millisecond)
	})

	AfterEach(func() {
		testServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when fetching all CVEs", func() {
		It("should fetch and paginate through all results", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(BeNumerically(">=", 5))
		})

		It("should extract CVE IDs with year paths", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx, nil)

			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("2023/cve-2023-1234"))
			Expect(records).To(HaveKey("2023/cve-2023-5678"))
			Expect(records).To(HaveKey("2024/cve-2024-0001"))
		})

		It("should store full NVD records", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx, nil)

			Expect(err).NotTo(HaveOccurred())

			record := records["2023/cve-2023-1234"]
			Expect(record).NotTo(BeNil())
			Expect(record["id"]).To(Equal("CVE-2023-1234"))
		})

		It("should return API URLs", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx, nil)
			Expect(err).NotTo(HaveOccurred())

			urls := manager.URLs()
			Expect(len(urls)).To(BeNumerically(">=", 1))
			Expect(urls[0]).To(ContainSubstring(testServer.URL))
		})
	})

	Context("when handling empty responses", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				resp := makeNVDResponse(0, 0, 0, nil)
				data, _ := json.Marshal(resp)
				w.Write(data)
			}))
			manager = nvd.NewManagerWithAPIURL(config, testServer.URL+"/rest/json/cves/2.0")
			manager.SetRetryWait(10 * time.Millisecond)
		})

		It("should return empty map for zero results", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("when handling API errors", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				resp := map[string]interface{}{
					"totalResults":   0,
					"startIndex":     0,
					"resultsPerPage": 0,
					"message":        "Invalid API Key",
				}
				data, _ := json.Marshal(resp)
				w.Write(data)
			}))
			manager = nvd.NewManagerWithAPIURL(config, testServer.URL+"/rest/json/cves/2.0")
			manager.SetRetryWait(10 * time.Millisecond)
		})

		It("should return error on API error message", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx, nil)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("API error"))
		})
	})

	Context("when handling HTTP errors", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			manager = nvd.NewManagerWithAPIURL(config, testServer.URL+"/rest/json/cves/2.0")
			manager.SetRetryWait(10 * time.Millisecond)
		})

		It("should return error on server error", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx, nil)

			Expect(err).To(HaveOccurred())
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.Get(ctx, nil)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("override application", func() {
		It("should apply override configurations", func() {
			record := makeCVE("CVE-2023-1234")

			override := map[string]interface{}{
				"cve": map[string]interface{}{
					"configurations": []interface{}{
						map[string]interface{}{
							"nodes": []interface{}{
								map[string]interface{}{
									"cpeMatch": []interface{}{
										map[string]interface{}{
											"criteria":   "cpe:2.3:a:override:test:1.0:*:*:*:*:*:*:*",
											"vulnerable": true,
										},
									},
								},
							},
						},
					},
				},
			}

			modified, result := nvd.ApplyOverride("CVE-2023-1234", record, override)
			Expect(modified).To(BeTrue())

			cve := result["cve"].(map[string]interface{})
			configs := cve["configurations"].([]interface{})
			Expect(len(configs)).To(BeNumerically(">=", 1))
		})

		It("should merge override references without duplicates", func() {
			record := makeCVE("CVE-2023-1234")

			override := map[string]interface{}{
				"cve": map[string]interface{}{
					"configurations": []interface{}{
						map[string]interface{}{
							"nodes": []interface{}{},
						},
					},
					"references": []interface{}{
						map[string]interface{}{"url": "https://example.com/cve-2023-1234"},
						map[string]interface{}{"url": "https://new-ref.example.com/"},
					},
				},
			}

			modified, result := nvd.ApplyOverride("CVE-2023-1234", record, override)
			Expect(modified).To(BeTrue())

			cve := result["cve"].(map[string]interface{})
			refs := cve["references"].([]interface{})
			Expect(len(refs)).To(Equal(2))
		})

		It("should not modify record when no override exists", func() {
			record := makeCVE("CVE-2023-1234")

			modified, result := nvd.ApplyOverride("CVE-2023-1234", record, nil)
			Expect(modified).To(BeFalse())
			Expect(result).To(Equal(record))
		})

		It("should not modify record when override has no configurations", func() {
			record := makeCVE("CVE-2023-1234")

			override := map[string]interface{}{
				"cve": map[string]interface{}{
					"references": []interface{}{},
				},
			}

			modified, _ := nvd.ApplyOverride("CVE-2023-1234", record, override)
			Expect(modified).To(BeFalse())
		})
	})

	Context("CVE ID helpers", func() {
		It("should convert CVE ID to hierarchical path", func() {
			Expect(nvd.CVEToID("CVE-2023-1234")).To(Equal("2023/cve-2023-1234"))
			Expect(nvd.CVEToID("CVE-2024-56789")).To(Equal("2024/cve-2024-56789"))
		})

		It("should extract CVE ID from hierarchical path", func() {
			Expect(nvd.RecordIDToCVE("2023/cve-2023-1234")).To(Equal("CVE-2023-1234"))
			Expect(nvd.RecordIDToCVE("2024/cve-2024-56789")).To(Equal("CVE-2024-56789"))
		})
	})

	Context("override file loading", func() {
		It("should load override files from extracted archive structure", func() {
			overrideDir := filepath.Join(tempDir, "input", "nvd-overrides", "data", "2023")
			Expect(os.MkdirAll(overrideDir, 0755)).NotTo(HaveOccurred())

			overrideData := map[string]interface{}{
				"cve": map[string]interface{}{
					"configurations": []interface{}{
						map[string]interface{}{
							"nodes": []interface{}{
								map[string]interface{}{
									"cpeMatch": []interface{}{
										map[string]interface{}{
											"criteria":   "cpe:2.3:a:override:test:1.0:*:*:*:*:*:*:*",
											"vulnerable": true,
										},
									},
								},
							},
						},
					},
				},
			}

			data, _ := json.MarshalIndent(overrideData, "", "  ")
			Expect(os.WriteFile(filepath.Join(overrideDir, "CVE-2023-1234.json"), data, 0644)).NotTo(HaveOccurred())

			logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

			o := nvd.NewOverrides(true, "", filepath.Join(tempDir, "input"), logger, nil)

			result := o.CVE("CVE-2023-1234")
			Expect(result).NotTo(BeNil())

			cves := o.CVEs()
			Expect(cves).To(ContainElement("CVE-2023-1234"))
		})

		It("should return nil for disabled overrides", func() {
			logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

			o := nvd.NewOverrides(false, "", tempDir, logger, nil)

			Expect(o.CVE("CVE-2023-1234")).To(BeNil())
			Expect(o.CVEs()).To(BeEmpty())
		})
	})
})
