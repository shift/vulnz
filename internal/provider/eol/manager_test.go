package eol_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
	"github.com/shift/vulnz/internal/provider/eol"
)

var _ = Describe("EOL Manager", func() {
	var (
		manager    *eol.Manager
		tempDir    string
		testServer *httptest.Server
		testData   map[string]interface{}
		config     provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "eol-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		testData = map[string]interface{}{
			"result": []interface{}{
				map[string]interface{}{
					"name": "ubuntu",
					"identifiers": []interface{}{
						map[string]interface{}{
							"type":  "purl",
							"value": "pkg:generic/ubuntu",
						},
					},
					"releases": []interface{}{
						map[string]interface{}{
							"name":         "22.04",
							"support":      "2027-04-01",
							"eol":          "2027-04-01",
							"latest":       "22.04.4",
							"lts":          true,
							"releaseDate":  "2022-04-01",
							"discontinued": "",
						},
						map[string]interface{}{
							"name":         "24.04",
							"support":      "2029-04-01",
							"eol":          "2034-04-01",
							"latest":       "24.04.1",
							"lts":          true,
							"releaseDate":  "2024-04-01",
							"discontinued": "",
						},
					},
				},
				map[string]interface{}{
					"name": "nodejs",
					"identifiers": []interface{}{
						map[string]interface{}{
							"type":  "purl",
							"value": "pkg:generic/nodejs",
						},
					},
					"releases": []interface{}{
						map[string]interface{}{
							"name":        "20",
							"support":     "2026-04-01",
							"eol":         "2026-04-01",
							"latest":      "20.18.0",
							"lts":         true,
							"releaseDate": "2023-04-01",
						},
					},
				},
			},
		}

		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(testData)
		}))

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "eol",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = eol.NewManager(testServer.URL, config)
	})

	AfterEach(func() {
		testServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when fetching EOL data", func() {
		It("should download and parse EOL data successfully", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(3))
		})

		It("should save raw data to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			inputPath := filepath.Join(tempDir, "input", "eol.json")
			content, readErr := os.ReadFile(inputPath)
			Expect(readErr).NotTo(HaveOccurred())

			var parsed map[string]interface{}
			jsonErr := json.Unmarshal(content, &parsed)
			Expect(jsonErr).NotTo(HaveOccurred())
			Expect(parsed).To(HaveKey("result"))
		})

		It("should create proper EOL records with lifecycle metadata", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["eol:ubuntu:22.04"]
			Expect(record).NotTo(BeNil())

			Expect(record["product"]).To(Equal("ubuntu"))
			Expect(record["cycle"]).To(Equal("22.04"))
			Expect(record["support"]).To(Equal("2027-04-01"))
			Expect(record["eol"]).To(Equal("2027-04-01"))
			Expect(record["latest"]).To(Equal("22.04.4"))
			Expect(record["lts"]).To(BeTrue())
			Expect(record["releaseDate"]).To(Equal("2022-04-01"))
			Expect(record["namespace"]).To(Equal("eol"))

			identifiers := record["identifiers"].(map[string]interface{})
			Expect(identifiers["purl"]).To(Equal("pkg:generic/ubuntu"))

			metadata := record["metadata"].(map[string]interface{})
			Expect(metadata["source"]).To(Equal("endoflife.date"))
			Expect(metadata["record_type"]).To(Equal("lifecycle"))
			Expect(metadata["product_name"]).To(Equal("ubuntu"))
			Expect(metadata["cycle_name"]).To(Equal("22.04"))
		})

		It("should handle products without identifiers", func() {
			testData = map[string]interface{}{
				"result": []interface{}{
					map[string]interface{}{
						"name": "generic-product",
						"releases": []interface{}{
							map[string]interface{}{
								"name":   "1.0",
								"eol":    "2024-01-01",
								"latest": "1.0.0",
							},
						},
					},
				},
			}

			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["eol:generic-product:1.0"]
			Expect(record).NotTo(BeNil())
			Expect(record["product"]).To(Equal("generic-product"))
			Expect(record["identifiers"]).To(BeNil())
		})

		It("should create records with correct keys", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(records).To(HaveKey("eol:ubuntu:22.04"))
			Expect(records).To(HaveKey("eol:ubuntu:24.04"))
			Expect(records).To(HaveKey("eol:nodejs:20"))
		})

		It("should handle multiple releases per product", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			ubuntu22 := records["eol:ubuntu:22.04"]
			ubuntu24 := records["eol:ubuntu:24.04"]
			Expect(ubuntu22).NotTo(BeNil())
			Expect(ubuntu24).NotTo(BeNil())
			Expect(ubuntu22["cycle"]).To(Equal("22.04"))
			Expect(ubuntu24["cycle"]).To(Equal("24.04"))
		})

		It("should skip products with empty name", func() {
			testData = map[string]interface{}{
				"result": []interface{}{
					map[string]interface{}{
						"name": "",
						"releases": []interface{}{
							map[string]interface{}{
								"name": "1.0",
								"eol":  "2024-01-01",
							},
						},
					},
					map[string]interface{}{
						"name": "valid-product",
						"releases": []interface{}{
							map[string]interface{}{
								"name": "2.0",
								"eol":  "2025-01-01",
							},
						},
					},
				},
			}

			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(1))
			Expect(records).To(HaveKey("eol:valid-product:2.0"))
		})

		It("should skip releases with empty name", func() {
			testData = map[string]interface{}{
				"result": []interface{}{
					map[string]interface{}{
						"name": "some-product",
						"releases": []interface{}{
							map[string]interface{}{
								"name": "",
								"eol":  "2024-01-01",
							},
							map[string]interface{}{
								"name": "1.0",
								"eol":  "2025-01-01",
							},
						},
					},
				},
			}

			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(1))
			Expect(records).To(HaveKey("eol:some-product:1.0"))
		})
	})

	Context("when handling HTTP errors", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			manager = eol.NewManager(testServer.URL, config)
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
			manager = eol.NewManager(testServer.URL, config)
		})

		It("should return error on invalid JSON", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse JSON"))
		})
	})

	Context("when handling empty result", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"result": []}`))
			}))
			manager = eol.NewManager(testServer.URL, config)
		})

		It("should return empty map for empty result", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("when handling products with no releases", func() {
		BeforeEach(func() {
			testData = map[string]interface{}{
				"result": []interface{}{
					map[string]interface{}{
						"name":     "no-releases-product",
						"releases": []interface{}{},
					},
					map[string]interface{}{
						"name": "product-with-releases",
						"releases": []interface{}{
							map[string]interface{}{
								"name": "1.0",
								"eol":  "2024-01-01",
							},
						},
					},
				},
			}
		})

		It("should only create records for products with releases", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(1))
			Expect(records).To(HaveKey("eol:product-with-releases:1.0"))
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
				json.NewEncoder(w).Encode(testData)
			}))
			manager = eol.NewManager(testServer.URL, config)

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			time.Sleep(5 * time.Millisecond)

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("URLs method", func() {
		It("should return the configured URL", func() {
			urls := manager.URLs()
			Expect(urls).To(HaveLen(1))
			Expect(urls[0]).To(Equal(testServer.URL))
		})
	})
})
