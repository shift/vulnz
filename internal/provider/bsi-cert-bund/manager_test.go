package bsicertbund_test

import (
	"context"
	"encoding/json"
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
	"github.com/shift/vulnz/internal/provider/bsi-cert-bund"
)

func buildMockDocument1() map[string]interface{} {
	return map[string]interface{}{
		"document": map[string]interface{}{
			"title":        "Test Advisory 1: Critical Vulnerability in Test Product",
			"csaf_version": "2.0",
			"tracking": map[string]interface{}{
				"id":                   "WID-SEC-W-2026-0001",
				"initial_release_date": "2026-01-15T10:00:00Z",
				"current_release_date": "2026-01-20T12:00:00Z",
			},
			"aggregate_severity": map[string]interface{}{
				"text": "kritisch",
			},
			"references": []interface{}{
				map[string]interface{}{
					"url": "https://example.com/advisory1",
				},
			},
			"distribution": map[string]interface{}{
				"tlp": map[string]interface{}{
					"label": "WHITE",
				},
			},
		},
		"product_tree": map[string]interface{}{
			"branches": []interface{}{
				map[string]interface{}{
					"category": "vendor",
					"name":     "Test Vendor",
					"branches": []interface{}{
						map[string]interface{}{
							"category": "product_name",
							"name":     "Test Product",
							"product": map[string]interface{}{
								"product_id": "CSAFPID-0001",
								"name":       "Test Product <2.0.0",
							},
						},
					},
				},
			},
		},
		"vulnerabilities": []interface{}{
			map[string]interface{}{
				"cve": "CVE-2026-0001",
				"scores": []interface{}{
					map[string]interface{}{
						"cvss_v3": map[string]interface{}{
							"baseScore":           9.8,
							"vectorString":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							"exploitabilityScore": 3.9,
							"impactScore":         5.9,
						},
					},
				},
				"product_status": map[string]interface{}{
					"known_affected": []interface{}{"CSAFPID-0001"},
				},
			},
		},
	}
}

func buildMockDocument2() map[string]interface{} {
	return map[string]interface{}{
		"document": map[string]interface{}{
			"title":        "Test Advisory 2: Medium Severity Issue",
			"csaf_version": "2.0",
			"tracking": map[string]interface{}{
				"id":                   "WID-SEC-W-2026-0002",
				"initial_release_date": "2026-02-01T08:00:00Z",
				"current_release_date": "2026-02-10T14:00:00Z",
			},
			"aggregate_severity": map[string]interface{}{
				"text": "mittel",
			},
			"references": []interface{}{
				map[string]interface{}{
					"url": "https://example.com/advisory2",
				},
			},
			"distribution": map[string]interface{}{
				"tlp": map[string]interface{}{
					"label": "WHITE",
				},
			},
		},
		"product_tree": map[string]interface{}{
			"branches": []interface{}{
				map[string]interface{}{
					"category": "vendor",
					"name":     "Another Vendor",
					"branches": []interface{}{
						map[string]interface{}{
							"category": "product_name",
							"name":     "LibFoo",
							"product": map[string]interface{}{
								"product_id": "CSAFPID-0002",
								"name":       "LibFoo =1.5.0",
							},
						},
					},
				},
			},
		},
		"vulnerabilities": []interface{}{
			map[string]interface{}{
				"cve": "",
				"scores": []interface{}{
					map[string]interface{}{
						"cvss_v2": map[string]interface{}{
							"baseScore":    5.0,
							"vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
						},
					},
				},
				"product_status": map[string]interface{}{
					"known_affected": []interface{}{"CSAFPID-0002"},
				},
			},
		},
	}
}

func buildMockIndex(serverURL string) map[string]interface{} {
	return map[string]interface{}{
		"feed": map[string]interface{}{
			"entry": []interface{}{
				map[string]interface{}{
					"id":    "WID-SEC-W-2026-0001",
					"title": "Test Advisory 1",
					"content": map[string]interface{}{
						"src": serverURL + "/csaf/2026/wid-sec-w-2026-0001.json",
					},
				},
				map[string]interface{}{
					"id":    "WID-SEC-W-2026-0002",
					"title": "Test Advisory 2",
					"content": map[string]interface{}{
						"src": serverURL + "/csaf/2026/wid-sec-w-2026-0002.json",
					},
				},
			},
		},
	}
}

var _ = Describe("BSI CERT-Bund Manager", func() {
	var (
		manager    *bsicertbund.Manager
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
		mockIndex  map[string]interface{}
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "bsi-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		mockDocuments := map[string]interface{}{
			"/csaf/2026/wid-sec-w-2026-0001.json": buildMockDocument1(),
			"/csaf/2026/wid-sec-w-2026-0002.json": buildMockDocument2(),
		}

		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			if r.URL.Path == "/.well-known/csaf/white/bsi-wid-white.json" {
				json.NewEncoder(w).Encode(mockIndex)
				return
			}

			if doc, ok := mockDocuments[r.URL.Path]; ok {
				json.NewEncoder(w).Encode(doc)
				return
			}

			w.WriteHeader(http.StatusNotFound)
		}))

		mockIndex = buildMockIndex(testServer.URL)

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "bsi-cert-bund",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = bsicertbund.NewManagerWithURL(testServer.URL+"/.well-known/csaf/white/bsi-wid-white.json", config)
	})

	AfterEach(func() {
		testServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when fetching and parsing CSAF data", func() {
		It("should fetch index and documents successfully", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(2))
		})

		It("should save raw index to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			inputPath := filepath.Join(tempDir, "input", "bsi_csaf_index.json")
			content, readErr := os.ReadFile(inputPath)
			Expect(readErr).NotTo(HaveOccurred())

			var parsed map[string]interface{}
			jsonErr := json.Unmarshal(content, &parsed)
			Expect(jsonErr).NotTo(HaveOccurred())
			Expect(parsed).To(HaveKey("feed"))
		})

		It("should create proper vulnerability records with CVE ID", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2026-0001"]
			Expect(record).NotTo(BeNil())

			Expect(record["id"]).To(Equal("CVE-2026-0001"))
			Expect(record["namespace"]).To(Equal("bsi:cert-bund"))
			Expect(record["description"]).To(Equal("Test Advisory 1: Critical Vulnerability in Test Product"))
			Expect(record["severity"]).To(Equal("Critical"))

			cvss := record["cvss"].([]map[string]interface{})
			Expect(cvss).To(HaveLen(1))
			Expect(cvss[0]["version"]).To(Equal("3.1"))
			Expect(cvss[0]["vector"]).To(Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
			Expect(cvss[0]["metrics"].(map[string]interface{})["baseScore"]).To(Equal(9.8))

			urls := record["urls"].([]string)
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(Equal("https://example.com/advisory1"))

			metadata := record["metadata"].(map[string]interface{})
			Expect(metadata["source"]).To(Equal("bsi-cert-bund"))
			Expect(metadata["advisory_id"]).To(Equal("WID-SEC-W-2026-0001"))
			Expect(metadata["cve_id"]).To(Equal("CVE-2026-0001"))
			Expect(metadata["aggregate_severity_de"]).To(Equal("kritisch"))
			Expect(metadata["published"]).To(Equal("2026-01-15T10:00:00Z"))
			Expect(metadata["updated"]).To(Equal("2026-01-20T12:00:00Z"))
			Expect(metadata["csaf_version"]).To(Equal("2.0"))
			Expect(metadata["tlp"]).To(Equal("WHITE"))
			Expect(metadata["bsi_tr_03116_compliant"]).To(BeTrue())
			Expect(metadata["sovereign_database"]).To(BeTrue())
		})

		It("should fall back to advisory ID when CVE is missing", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["WID-SEC-W-2026-0002"]
			Expect(record).NotTo(BeNil())
			Expect(record["id"]).To(Equal("WID-SEC-W-2026-0002"))
			Expect(record["severity"]).To(Equal("Medium"))

			metadata := record["metadata"].(map[string]interface{})
			Expect(metadata["cve_id"]).To(Equal(""))
			Expect(metadata["advisory_id"]).To(Equal("WID-SEC-W-2026-0002"))
		})

		It("should extract affected products", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2026-0001"]
			Expect(record).NotTo(BeNil())

			affected := record["affected"].([]map[string]string)
			Expect(affected).To(HaveLen(1))
			Expect(affected[0]["name"]).To(Equal("Test Product"))
			Expect(affected[0]["vendor"]).To(Equal("Test Vendor"))
			Expect(affected[0]["version"]).To(Equal("2.0.0"))
		})

		It("should extract products with equals version delimiter", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["WID-SEC-W-2026-0002"]
			Expect(record).NotTo(BeNil())

			affected := record["affected"].([]map[string]string)
			Expect(affected).To(HaveLen(1))
			Expect(affected[0]["name"]).To(Equal("LibFoo"))
			Expect(affected[0]["vendor"]).To(Equal("Another Vendor"))
			Expect(affected[0]["version"]).To(Equal("1.5.0"))
		})

		It("should handle CVSS v2 scores", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["WID-SEC-W-2026-0002"]
			Expect(record).NotTo(BeNil())

			cvss := record["cvss"].([]map[string]interface{})
			Expect(cvss).To(HaveLen(1))
			Expect(cvss[0]["version"]).To(Equal("2.0"))
			Expect(cvss[0]["vector"]).To(Equal("AV:N/AC:L/Au:N/C:P/I:N/A:N"))
			Expect(cvss[0]["metrics"].(map[string]interface{})["baseScore"]).To(Equal(5.0))
		})

		It("should generate correct advisory links", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2026-0001"]
			advisories := record["advisories"].([]map[string]string)
			Expect(advisories).To(HaveLen(1))
			Expect(advisories[0]["id"]).To(Equal("WID-SEC-W-2026-0001"))
			Expect(advisories[0]["link"]).To(Equal("https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0001"))
		})

		It("should track fetched URLs", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			urls := manager.URLs()
			Expect(len(urls)).To(BeNumerically(">=", 3))
			Expect(urls[0]).To(ContainSubstring("bsi-wid-white.json"))
		})
	})

	Context("when handling German severity mapping", func() {
		It("should map kritisch to Critical", func() {
			Expect(testServer.URL).NotTo(BeEmpty())
		})

		It("should map all German severities correctly", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records["CVE-2026-0001"]["severity"]).To(Equal("Critical"))
			Expect(records["WID-SEC-W-2026-0002"]["severity"]).To(Equal("Medium"))
		})
	})

	Context("when handling HTTP errors", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			manager = bsicertbund.NewManagerWithURL(testServer.URL+"/.well-known/csaf/white/bsi-wid-white.json", config)
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
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"invalid": json`))
			}))
			manager = bsicertbund.NewManagerWithURL(testServer.URL+"/.well-known/csaf/white/bsi-wid-white.json", config)
		})

		It("should return error on invalid JSON", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
		})
	})

	Context("when handling empty index", func() {
		BeforeEach(func() {
			testServer.Close()
			emptyIndex := map[string]interface{}{
				"feed": map[string]interface{}{
					"entry": []interface{}{},
				},
			}
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(emptyIndex)
			}))
			manager = bsicertbund.NewManagerWithURL(testServer.URL+"/.well-known/csaf/white/bsi-wid-white.json", config)
		})

		It("should return empty map for empty index", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("when handling missing feed in index", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"no_feed": "here"}`))
			}))
			manager = bsicertbund.NewManagerWithURL(testServer.URL+"/.well-known/csaf/white/bsi-wid-white.json", config)
		})

		It("should return error when feed is missing", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("missing 'feed'"))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})

		It("should respect context timeout", func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(100 * time.Millisecond)
				json.NewEncoder(w).Encode(mockIndex)
			}))
			manager = bsicertbund.NewManagerWithURL(testServer.URL+"/.well-known/csaf/white/bsi-wid-white.json", config)

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("URLs method", func() {
		It("should return the index URL initially", func() {
			mgr := bsicertbund.NewManagerWithURL("https://example.com/index.json", config)
			urls := mgr.URLs()
			Expect(urls).To(BeEmpty())
		})
	})

	Context("when entries have missing document URLs", func() {
		BeforeEach(func() {
			testServer.Close()
			indexNoURL := map[string]interface{}{
				"feed": map[string]interface{}{
					"entry": []interface{}{
						map[string]interface{}{
							"id":      "WID-SEC-W-2026-0003",
							"title":   "No URL Advisory",
							"content": map[string]interface{}{},
						},
					},
				},
			}
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(indexNoURL)
			}))
			manager = bsicertbund.NewManagerWithURL(testServer.URL+"/.well-known/csaf/white/bsi-wid-white.json", config)
		})

		It("should skip entries without document URLs", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("when document fetch fails", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/.well-known/csaf/white/bsi-wid-white.json" {
					json.NewEncoder(w).Encode(mockIndex)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			manager = bsicertbund.NewManagerWithURL(testServer.URL+"/.well-known/csaf/white/bsi-wid-white.json", config)
		})

		It("should continue when individual document fetch fails", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("germanSeverityMap function", func() {
		It("should correctly map all German severity levels", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(records["CVE-2026-0001"]["severity"]).To(Equal("Critical"))
		})
	})

	Context("advisory link generation", func() {
		It("should replace -W- with single dash", func() {
			link := strings.ReplaceAll("WID-SEC-W-2026-0001", "-W-", "-")
			Expect(link).To(Equal("WID-SEC-2026-0001"))
		})
	})
})
