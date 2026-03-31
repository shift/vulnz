package rocky_test

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
	"github.com/shift/vulnz/internal/provider/rocky"
)

func sampleAdvisory(id, summary string) map[string]interface{} {
	return map[string]interface{}{
		"id":             id,
		"schema_version": "1.7.0",
		"summary":        summary,
		"affected": []interface{}{
			map[string]interface{}{
				"package": map[string]interface{}{
					"name":      "bash",
					"ecosystem": "Rocky Linux:8",
				},
				"ranges": []interface{}{
					map[string]interface{}{
						"type": "ECOSYSTEM",
						"events": []interface{}{
							map[string]interface{}{"introduced": "0"},
							map[string]interface{}{"fixed": "4.4.20-4.el8_6"},
						},
					},
				},
			},
			map[string]interface{}{
				"package": map[string]interface{}{
					"name":      "openssl",
					"ecosystem": "Rocky Linux:9",
				},
				"ranges": []interface{}{
					map[string]interface{}{
						"type": "ECOSYSTEM",
						"events": []interface{}{
							map[string]interface{}{"introduced": "0"},
							map[string]interface{}{"fixed": "3.0.1-43.el9_2"},
						},
					},
				},
			},
		},
	}
}

func makePageResponse(advisories []interface{}, next string) map[string]interface{} {
	links := map[string]interface{}{}
	if next != "" {
		links["next"] = next
	}
	return map[string]interface{}{
		"links":      links,
		"advisories": advisories,
	}
}

func testManagerConfig(tempDir string) provider.Config {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	return provider.Config{
		Name:      "rocky",
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

var _ = Describe("Rocky Linux Manager", func() {
	var (
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "rocky-manager-test-*")
		Expect(err).NotTo(HaveOccurred())
		config = testManagerConfig(tempDir)
	})

	AfterEach(func() {
		if testServer != nil {
			testServer.Close()
			testServer = nil
		}
		os.RemoveAll(tempDir)
	})

	Context("when fetching advisories", func() {
		It("should fetch and parse a single page of advisories", func() {
			advisories := []interface{}{
				sampleAdvisory("RSA-2024:1001", "Test advisory 1"),
				sampleAdvisory("RSA-2024:1002", "Test advisory 2"),
			}

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makePageResponse(advisories, ""))
			}))

			manager := rocky.NewManagerWithURL(testServer.URL+"/api/v3/osv/", config)
			ctx := context.Background()
			results, urls, err := manager.GetAllAdvisories(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(2))
			Expect(urls).NotTo(BeEmpty())
			Expect(urls[0]).To(ContainSubstring("api/v3/osv"))
		})

		It("should handle pagination correctly", func() {
			page1 := []interface{}{sampleAdvisory("RSA-2024:2001", "Page 1 advisory")}
			page2 := []interface{}{sampleAdvisory("RSA-2024:2002", "Page 2 advisory")}

			requestCount := 0
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if !strings.Contains(r.URL.RawQuery, "page=2") {
					json.NewEncoder(w).Encode(makePageResponse(page1, "/api/v3/osv/?page=2"))
				} else {
					json.NewEncoder(w).Encode(makePageResponse(page2, ""))
				}
				requestCount++
			}))

			manager := rocky.NewManagerWithURL(testServer.URL+"/api/v3/osv/", config)
			ctx := context.Background()
			results, _, err := manager.GetAllAdvisories(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(2))
			Expect(results).To(HaveKey("RSA-2024:2001"))
			Expect(results).To(HaveKey("RSA-2024:2002"))
			Expect(requestCount).To(Equal(2))
		})

		It("should normalize ecosystem from Rocky Linux:8 to rocky:8", func() {
			advisories := []interface{}{
				sampleAdvisory("RSA-2024:3001", "Ecosystem normalization test"),
			}

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makePageResponse(advisories, ""))
			}))

			manager := rocky.NewManagerWithURL(testServer.URL+"/api/v3/osv/", config)
			ctx := context.Background()
			results, _, err := manager.GetAllAdvisories(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := results["RSA-2024:3001"]
			Expect(record).NotTo(BeNil())

			affected := record["affected"].([]interface{})
			ecosystems := []string{}
			for _, aff := range affected {
				pkg := aff.(map[string]interface{})
				pkgInfo := pkg["package"].(map[string]interface{})
				ecosystems = append(ecosystems, pkgInfo["ecosystem"].(string))
			}
			Expect(ecosystems).To(ContainElement("rocky:8"))
			Expect(ecosystems).To(ContainElement("rocky:9"))
			Expect(ecosystems).NotTo(ContainElement("Rocky Linux:8"))
			Expect(ecosystems).NotTo(ContainElement("Rocky Linux:9"))
		})

		It("should preserve all advisory fields", func() {
			advisories := []interface{}{
				sampleAdvisory("RSA-2024:4001", "Field preservation test"),
			}

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makePageResponse(advisories, ""))
			}))

			manager := rocky.NewManagerWithURL(testServer.URL+"/api/v3/osv/", config)
			ctx := context.Background()
			results, _, err := manager.GetAllAdvisories(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := results["RSA-2024:4001"]
			Expect(record["id"]).To(Equal("RSA-2024:4001"))
			Expect(record["schema_version"]).To(Equal("1.7.0"))
			Expect(record["summary"]).To(Equal("Field preservation test"))
		})

		It("should skip advisories with empty ID", func() {
			emptyAdvisory := map[string]interface{}{
				"id":             "",
				"schema_version": "1.7.0",
				"summary":        "Empty ID",
			}
			validAdvisory := sampleAdvisory("RSA-2024:5001", "Valid advisory")

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makePageResponse([]interface{}{emptyAdvisory, validAdvisory}, ""))
			}))

			manager := rocky.NewManagerWithURL(testServer.URL+"/api/v3/osv/", config)
			ctx := context.Background()
			results, _, err := manager.GetAllAdvisories(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(1))
			Expect(results).To(HaveKey("RSA-2024:5001"))
		})

		It("should handle empty results", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makePageResponse([]interface{}{}, ""))
			}))

			manager := rocky.NewManagerWithURL(testServer.URL+"/api/v3/osv/", config)
			ctx := context.Background()
			results, _, err := manager.GetAllAdvisories(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(BeEmpty())
		})
	})

	Context("when handling HTTP errors", func() {
		It("should return error on HTTP failure", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))

			manager := rocky.NewManagerWithURL(testServer.URL+"/api/v3/osv/", config)
			ctx := context.Background()
			_, _, err := manager.GetAllAdvisories(ctx)

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

			manager := rocky.NewManagerWithURL(testServer.URL+"/api/v3/osv/", config)
			ctx := context.Background()
			_, _, err := manager.GetAllAdvisories(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse JSON"))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(100 * time.Millisecond)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makePageResponse([]interface{}{}, ""))
			}))

			manager := rocky.NewManagerWithURL(testServer.URL+"/api/v3/osv/", config)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, _, err := manager.GetAllAdvisories(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("normalizeEcosystem", func() {
		It("should handle advisories with no affected field", func() {
			advisory := map[string]interface{}{
				"id":      "RSA-2024:6001",
				"summary": "No affected field",
			}

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makePageResponse([]interface{}{advisory}, ""))
			}))

			manager := rocky.NewManagerWithURL(testServer.URL+"/api/v3/osv/", config)
			ctx := context.Background()
			results, _, err := manager.GetAllAdvisories(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(1))
		})

		It("should not modify non-Rocky Linux ecosystems", func() {
			advisory := map[string]interface{}{
				"id":      "RSA-2024:7001",
				"summary": "Mixed ecosystem test",
				"affected": []interface{}{
					map[string]interface{}{
						"package": map[string]interface{}{
							"name":      "somepkg",
							"ecosystem": "crates.io",
						},
					},
				},
			}

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(makePageResponse([]interface{}{advisory}, ""))
			}))

			manager := rocky.NewManagerWithURL(testServer.URL+"/api/v3/osv/", config)
			ctx := context.Background()
			results, _, err := manager.GetAllAdvisories(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := results["RSA-2024:7001"]
			affected := record["affected"].([]interface{})
			pkg := affected[0].(map[string]interface{})
			pkgInfo := pkg["package"].(map[string]interface{})
			Expect(pkgInfo["ecosystem"]).To(Equal("crates.io"))
		})
	})
})
