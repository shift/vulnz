package euvd_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/euvd"
)

func makeSearchResponse(items []interface{}, total int) map[string]interface{} {
	return map[string]interface{}{
		"items": items,
		"total": total,
	}
}

func sampleRecord(id, cveID string) map[string]interface{} {
	return map[string]interface{}{
		"id":               id,
		"enisaUuid":        "test-uuid-" + id,
		"description":      "Test vulnerability " + id,
		"datePublished":    "Mar 24, 2026, 5:53:12 PM",
		"dateUpdated":      "Mar 24, 2026, 5:53:12 PM",
		"baseScore":        9.4,
		"baseScoreVersion": "4.0",
		"baseScoreVector":  "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
		"references":       "https://nvd.nist.gov/vuln/detail/" + cveID + "\nhttps://example.com/advisory",
		"aliases":          cveID + "\nGHSA-test123",
		"assigner":         "test_assigner",
		"epss":             20.84,
		"exploitedSince":   "Mar 26, 2026, 12:00:00 AM",
		"enisaIdProduct": []interface{}{
			map[string]interface{}{
				"id": "prod-1",
				"product": map[string]interface{}{
					"name": "TestProduct",
				},
				"product_version": "1.0.0 <2.0.0",
			},
		},
		"enisaIdVendor": []interface{}{
			map[string]interface{}{
				"id": "vendor-1",
				"vendor": map[string]interface{}{
					"name": "TestVendor",
				},
			},
		},
	}
}

func testConfig(tempDir string) provider.Config {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	return provider.Config{
		Name:      "euvd",
		Workspace: tempDir,
		HTTP: provider.HTTPConfig{
			Timeout:      10 * time.Second,
			UserAgent:    "vulnz-go-test/1.0",
			MaxRetries:   3,
			RateLimitRPS: 10,
		},
		Logger: logger,
	}
}

var _ = Describe("EUVD Manager", func() {
	var (
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "euvd-manager-test-*")
		Expect(err).NotTo(HaveOccurred())
		config = testConfig(tempDir)
	})

	AfterEach(func() {
		if testServer != nil {
			testServer.Close()
			testServer = nil
		}
		os.RemoveAll(tempDir)
	})

	Context("when fetching exploited vulnerabilities", func() {
		It("should fetch and parse a single page of records", func() {
			records := []interface{}{
				sampleRecord("EUVD-2026-1001", "CVE-2026-1001"),
				sampleRecord("EUVD-2026-1002", "CVE-2026-1002"),
			}

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makeSearchResponse(records, 2))
			}))

			manager := euvd.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			results, urls, err := manager.GetAllExploited(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(2))
			Expect(urls).NotTo(BeEmpty())
			Expect(urls[0]).To(ContainSubstring("exploited=true"))
		})

		It("should handle pagination correctly", func() {
			// To trigger 2 pages with MaxPageSize=100, we need total > 100.
			// Page 0: first 100 records (simulated as 1 here), page 1: remaining.
			page0 := []interface{}{sampleRecord("EUVD-2026-2001", "CVE-2026-2001")}
			page1 := []interface{}{sampleRecord("EUVD-2026-2002", "CVE-2026-2002")}

			requestCount := 0
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.Contains(r.URL.RawQuery, "page=0") {
					json.NewEncoder(w).Encode(makeSearchResponse(page0, 101))
				} else if strings.Contains(r.URL.RawQuery, "page=1") {
					json.NewEncoder(w).Encode(makeSearchResponse(page1, 101))
				}
				requestCount++
			}))

			manager := euvd.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			results, _, err := manager.GetAllExploited(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(2))
			Expect(results).To(HaveKey("EUVD-2026-2001"))
			Expect(results).To(HaveKey("EUVD-2026-2002"))
			Expect(requestCount).To(BeNumerically(">=", 2))
		})

		It("should enrich records with EU CRA metadata", func() {
			records := []interface{}{
				sampleRecord("EUVD-2026-3001", "CVE-2026-3001"),
			}

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makeSearchResponse(records, 1))
			}))

			manager := euvd.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			results, _, err := manager.GetAllExploited(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := results["EUVD-2026-3001"]
			Expect(record).NotTo(BeNil())
			Expect(record["exploited_in_wild"]).To(BeTrue())
			Expect(record["namespace"]).To(Equal("euvd"))
			Expect(record["baseScore"]).To(Equal(9.4))
			Expect(record["epss"]).To(Equal(20.84))

			metadata := record["metadata"].(map[string]interface{})
			Expect(metadata["source"]).To(Equal("euvd-exploited"))
			Expect(metadata["eu_cra_active_exploitation"]).To(BeTrue())
			Expect(metadata["requires_immediate_action"]).To(BeTrue())
		})

		It("should extract CVE IDs from aliases", func() {
			records := []interface{}{
				sampleRecord("EUVD-2026-4001", "CVE-2026-4001"),
			}

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makeSearchResponse(records, 1))
			}))

			manager := euvd.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			results, _, err := manager.GetAllExploited(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := results["EUVD-2026-4001"]
			cveIDs := record["cveIds"].([]string)
			Expect(cveIDs).To(ContainElement("CVE-2026-4001"))
		})

		It("should parse affected products and vendors", func() {
			records := []interface{}{
				sampleRecord("EUVD-2026-5001", "CVE-2026-5001"),
			}

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makeSearchResponse(records, 1))
			}))

			manager := euvd.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			results, _, err := manager.GetAllExploited(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := results["EUVD-2026-5001"]
			products := record["affectedProducts"].([]map[string]string)
			Expect(products).To(HaveLen(1))
			Expect(products[0]["name"]).To(Equal("TestProduct"))
			Expect(products[0]["version"]).To(Equal("1.0.0 <2.0.0"))

			vendors := record["vendors"].([]string)
			Expect(vendors).To(ContainElement("TestVendor"))
		})

		It("should parse references as a list", func() {
			records := []interface{}{
				sampleRecord("EUVD-2026-6001", "CVE-2026-6001"),
			}

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makeSearchResponse(records, 1))
			}))

			manager := euvd.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			results, _, err := manager.GetAllExploited(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := results["EUVD-2026-6001"]
			refs := record["references"].([]string)
			Expect(refs).To(HaveLen(2))
			Expect(refs[0]).To(ContainSubstring("nvd.nist.gov"))
		})

		It("should handle empty results", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makeSearchResponse([]interface{}{}, 0))
			}))

			manager := euvd.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			results, _, err := manager.GetAllExploited(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(BeEmpty())
		})
	})

	Context("when handling HTTP errors", func() {
		It("should return error on HTTP failure", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))

			manager := euvd.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			_, _, err := manager.GetAllExploited(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unexpected status code"))
		})
	})

	Context("when handling malformed data", func() {
		It("should return error on invalid JSON", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{invalid json`))
			}))

			manager := euvd.NewManagerWithURL(testServer.URL, config)
			ctx := context.Background()
			_, _, err := manager.GetAllExploited(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse JSON"))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(100 * time.Millisecond)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makeSearchResponse([]interface{}{}, 0))
			}))

			manager := euvd.NewManagerWithURL(testServer.URL, config)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, _, err := manager.GetAllExploited(ctx)
			Expect(err).To(HaveOccurred())
		})
	})
})
