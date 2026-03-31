package chainguardlibraries_test

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
	chainguardlibraries "github.com/shift/vulnz/internal/provider/chainguard-libraries"
)

var _ = Describe("Chainguard Libraries Manager", func() {
	var (
		manager    *chainguardlibraries.Manager
		tempDir    string
		testServer *httptest.Server
		config     provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "cglib-manager-test-*")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if testServer != nil {
			testServer.Close()
		}
		os.RemoveAll(tempDir)
	})

	setupConfig := func() {
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))

		config = provider.Config{
			Name:      "chainguard-libraries",
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

	setupMockServer := func(indexData []interface{}, docHandlers map[string]interface{}) {
		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			if r.URL.Path == "/index" || r.URL.Path == "/" {
				for i, entry := range indexData {
					if m, ok := entry.(map[string]interface{}); ok {
						if id, ok := m["@id"].(string); ok {
							if strings.HasPrefix(id, "PLACEHOLDER") {
								m["@id"] = strings.Replace(id, "PLACEHOLDER", testServer.URL, 1)
								indexData[i] = m
							}
						}
					}
				}
				json.NewEncoder(w).Encode(indexData)
				return
			}

			for path, doc := range docHandlers {
				if r.URL.Path == path {
					json.NewEncoder(w).Encode(doc)
					return
				}
			}

			w.WriteHeader(http.StatusNotFound)
		}))

		manager = chainguardlibraries.NewManager(testServer.URL+"/index", config)
	}

	Context("when fetching index and documents", func() {
		BeforeEach(func() {
			setupConfig()

			doc1 := map[string]interface{}{
				"@context":  "https://openvex.dev/ns/v0.2.0",
				"@id":       "https://libraries.cgr.dev/openvex/v1/GHSA-abc1",
				"author":    "chainguard",
				"timestamp": "2025-01-15T00:00:00Z",
				"product": map[string]interface{}{
					"@id": "pkg:pypi/requests@2.31.0",
				},
				"statements": []interface{}{
					map[string]interface{}{
						"vulnerability":    "GHSA-abc1",
						"status":           "fixed",
						"action_statement": "Upgrade to requests@2.32.0",
					},
				},
			}

			doc2 := map[string]interface{}{
				"@context":  "https://openvex.dev/ns/v0.2.0",
				"@id":       "https://libraries.cgr.dev/openvex/v1/GHSA-def2",
				"author":    "chainguard",
				"timestamp": "2025-02-01T00:00:00Z",
				"product": map[string]interface{}{
					"@id": "pkg:pypi/flask@3.0.0",
				},
				"statements": []interface{}{
					map[string]interface{}{
						"vulnerability": "GHSA-def2",
						"status":        "not_affected",
						"justification": "component is not vulnerable",
					},
					map[string]interface{}{
						"vulnerability":    "CVE-2025-0001",
						"status":           "fixed",
						"action_statement": "Update flask to 3.1.0",
					},
				},
			}

			indexData := []interface{}{
				map[string]interface{}{
					"@id":   "PLACEHOLDER/doc1.json",
					"@type": "https://openvex.dev/ns/v0.2.0",
				},
				map[string]interface{}{
					"@id":   "PLACEHOLDER/doc2.json",
					"@type": "https://openvex.dev/ns/v0.2.0",
				},
			}

			docHandlers := map[string]interface{}{
				"/doc1.json": doc1,
				"/doc2.json": doc2,
			}

			setupMockServer(indexData, docHandlers)
		})

		It("should fetch and parse pypi-only OpenVEX documents", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(2))
			Expect(records).To(HaveKey("GHSA-abc1"))
			Expect(records).To(HaveKey("CVE-2025-0001"))
		})

		It("should skip not_affected statements", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(HaveKey("GHSA-def2"))
		})

		It("should create proper vulnerability records", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())

			record := records["GHSA-abc1"]
			Expect(record).NotTo(BeNil())
			Expect(record["name"]).To(Equal("GHSA-abc1"))
			Expect(record["namespace"]).To(Equal("chainguard-libraries:pypi"))
			Expect(record["severity"]).To(Equal("Unknown"))
			Expect(record["link"]).To(Equal("https://libraries.cgr.dev/openvex/v1/GHSA-abc1"))
			Expect(record["description"]).To(Equal("Upgrade to requests@2.32.0"))

			fixedIn := record["fixedIn"].([]map[string]interface{})
			Expect(fixedIn).To(HaveLen(1))
			fix := fixedIn[0]
			Expect(fix["name"]).To(Equal("requests"))
			Expect(fix["version"]).To(Equal("2.31.0"))
			Expect(fix["versionFormat"]).To(Equal("pypi"))
		})

		It("should save index to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			inputPath := filepath.Join(tempDir, "input", "all.json")
			content, readErr := os.ReadFile(inputPath)
			Expect(readErr).NotTo(HaveOccurred())

			var parsed []interface{}
			jsonErr := json.Unmarshal(content, &parsed)
			Expect(jsonErr).NotTo(HaveOccurred())
			Expect(len(parsed)).To(Equal(2))
		})

		It("should return all fetched URLs", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			urls := manager.URLs()
			Expect(urls).To(HaveLen(3))
		})
	})

	Context("when filtering by ecosystem", func() {
		BeforeEach(func() {
			setupConfig()

			npmDoc := map[string]interface{}{
				"@context": "https://openvex.dev/ns/v0.2.0",
				"@id":      "https://libraries.cgr.dev/openvex/v1/GHSA-npm1",
				"author":   "chainguard",
				"product": map[string]interface{}{
					"@id": "pkg:npm/lodash@4.17.21",
				},
				"statements": []interface{}{
					map[string]interface{}{
						"vulnerability": "GHSA-npm1",
						"status":        "fixed",
					},
				},
			}

			pypiDoc := map[string]interface{}{
				"@context": "https://openvex.dev/ns/v0.2.0",
				"@id":      "https://libraries.cgr.dev/openvex/v1/GHSA-pypi1",
				"author":   "chainguard",
				"product": map[string]interface{}{
					"@id": "pkg:pypi/django@5.0.0",
				},
				"statements": []interface{}{
					map[string]interface{}{
						"vulnerability": "GHSA-pypi1",
						"status":        "fixed",
					},
				},
			}

			indexData := []interface{}{
				map[string]interface{}{
					"@id":   "PLACEHOLDER/npm.json",
					"@type": "https://openvex.dev/ns/v0.2.0",
				},
				map[string]interface{}{
					"@id":   "PLACEHOLDER/pypi.json",
					"@type": "https://openvex.dev/ns/v0.2.0",
				},
			}

			docHandlers := map[string]interface{}{
				"/npm.json":  npmDoc,
				"/pypi.json": pypiDoc,
			}

			setupMockServer(indexData, docHandlers)
		})

		It("should only include pypi ecosystem records", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(len(records)).To(Equal(1))
			Expect(records).To(HaveKey("GHSA-pypi1"))
			Expect(records).NotTo(HaveKey("GHSA-npm1"))
		})
	})

	Context("when handling HTTP errors", func() {
		BeforeEach(func() {
			setupConfig()

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))

			manager = chainguardlibraries.NewManager(testServer.URL, config)
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
			setupConfig()

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"invalid": json`))
			}))

			manager = chainguardlibraries.NewManager(testServer.URL, config)
		})

		It("should return error on invalid JSON", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse index JSON"))
		})
	})

	Context("when handling empty index", func() {
		BeforeEach(func() {
			setupConfig()

			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[]`))
			}))

			manager = chainguardlibraries.NewManager(testServer.URL, config)
		})

		It("should return empty map for empty index", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(Equal(0))
		})
	})

	Context("when handling context cancellation", func() {
		It("should respect context cancellation", func() {
			setupConfig()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(100 * time.Millisecond)
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`[]`))
			}))

			manager = chainguardlibraries.NewManager(testServer.URL, config)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := manager.Get(ctx)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("PURL parsing", func() {
		It("should parse valid pypi PURLs", func() {
			info, err := chainguardlibraries.ParsePURL("pkg:pypi/requests@2.31.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Type).To(Equal("pypi"))
			Expect(info.Name).To(Equal("requests"))
			Expect(info.Version).To(Equal("2.31.0"))
		})

		It("should parse PURLs with namespace", func() {
			info, err := chainguardlibraries.ParsePURL("pkg:pypi/some-namespace/requests@2.31.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Type).To(Equal("pypi"))
			Expect(info.Name).To(Equal("some-namespace/requests"))
			Expect(info.Version).To(Equal("2.31.0"))
		})

		It("should reject PURLs without pkg: prefix", func() {
			_, err := chainguardlibraries.ParsePURL("pypi/requests@2.31.0")
			Expect(err).To(HaveOccurred())
		})

		It("should reject PURLs without version", func() {
			_, err := chainguardlibraries.ParsePURL("pkg:pypi/requests")
			Expect(err).To(HaveOccurred())
		})
	})
})
