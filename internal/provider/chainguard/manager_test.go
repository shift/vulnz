package chainguard_test

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
	"github.com/shift/vulnz/internal/provider/chainguard"
)

var _ = Describe("Chainguard Manager", func() {
	var (
		manager    *chainguard.Manager
		tempDir    string
		testServer *httptest.Server
		testData   map[string]interface{}
		config     provider.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "chainguard-manager-test-*")
		Expect(err).NotTo(HaveOccurred())

		testData = map[string]interface{}{
			"apkurl":    "{{urlprefix}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk",
			"archs":     []string{"x86_64", "aarch64"},
			"reponame":  "chainguard",
			"urlprefix": "https://packages.cgr.dev",
			"packages": []interface{}{
				map[string]interface{}{
					"pkg": map[string]interface{}{
						"name": "test-pkg",
						"secfixes": map[string]interface{}{
							"1.0.0-r0": []string{"CVE-2023-1234"},
							"1.0.1-r0": []string{"CVE-2023-5678", "GHSA-1234-abcd"},
							"1.0.2-r0": []string{"CVE-2024-9999"},
						},
					},
				},
				map[string]interface{}{
					"pkg": map[string]interface{}{
						"name": "another-pkg",
						"secfixes": map[string]interface{}{
							"2.0.0-r0": []string{"CVE-2023-1234"},
							"2.1.0-r0": []string{"CVE-2025-0001"},
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
			Name:      "chainguard",
			Workspace: tempDir,
			HTTP: provider.HTTPConfig{
				Timeout:      10 * time.Second,
				UserAgent:    "vulnz-go-test/1.0",
				MaxRetries:   3,
				RateLimitRPS: 10,
			},
			Logger: logger,
		}

		manager = chainguard.NewManager(testServer.URL, config)
	})

	AfterEach(func() {
		testServer.Close()
		os.RemoveAll(tempDir)
	})

	Context("when fetching chainguard data", func() {
		It("should download and parse security db successfully", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
			Expect(len(records)).To(BeNumerically(">", 0))
		})

		It("should save raw data to workspace", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			inputPath := filepath.Join(tempDir, "input", "security.json")
			content, readErr := os.ReadFile(inputPath)
			Expect(readErr).NotTo(HaveOccurred())

			var parsed map[string]interface{}
			jsonErr := json.Unmarshal(content, &parsed)
			Expect(jsonErr).NotTo(HaveOccurred())
			Expect(parsed).To(HaveKey("packages"))
		})

		It("should create proper vulnerability records with correct namespace", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2023-1234"]
			Expect(record).NotTo(BeNil())

			vuln := record["Vulnerability"].(map[string]interface{})
			Expect(vuln["Name"]).To(Equal("CVE-2023-1234"))
			Expect(vuln["NamespaceName"]).To(Equal("chainguard:rolling"))
			Expect(vuln["Severity"]).To(Equal("Unknown"))
			Expect(vuln["Link"]).To(ContainSubstring("CVE-2023-1234"))
		})

		It("should accumulate FixedIn entries across packages", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["CVE-2023-1234"]
			Expect(record).NotTo(BeNil())

			vuln := record["Vulnerability"].(map[string]interface{})
			fixedIn := vuln["FixedIn"].([]interface{})

			Expect(len(fixedIn)).To(Equal(2))
		})

		It("should set VersionFormat to apk for all FixedIn entries", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			for vulnID, record := range records {
				vuln := record["Vulnerability"].(map[string]interface{})
				fixedInList := vuln["FixedIn"].([]interface{})

				for _, fi := range fixedInList {
					entry := fi.(map[string]interface{})
					Expect(entry["VersionFormat"]).To(Equal("apk"), "Vulnerability %s should have VersionFormat=apk", vulnID)
					Expect(entry["NamespaceName"]).To(Equal("chainguard:rolling"), "Vulnerability %s should have NamespaceName=chainguard:rolling", vulnID)
				}
			}
		})

		It("should handle GHSA identifiers", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())

			record := records["GHSA-1234-abcd"]
			Expect(record).NotTo(BeNil())

			vuln := record["Vulnerability"].(map[string]interface{})
			Expect(vuln["Name"]).To(Equal("GHSA-1234-abcd"))
		})

		It("should skip empty vulnerability IDs", func() {
			testData["packages"] = []interface{}{
				map[string]interface{}{
					"pkg": map[string]interface{}{
						"name": "empty-pkg",
						"secfixes": map[string]interface{}{
							"1.0.0-r0": []string{"", "CVE-2023-1111"},
						},
					},
				},
			}

			ctx := context.Background()
			records, err := manager.Get(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(HaveKey("CVE-2023-1111"))
			Expect(records).NotTo(HaveKey(""))
		})
	})

	Context("when handling HTTP errors", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			manager = chainguard.NewManager(testServer.URL, config)
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
			manager = chainguard.NewManager(testServer.URL, config)
		})

		It("should return error on invalid JSON", func() {
			ctx := context.Background()
			_, err := manager.Get(ctx)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse JSON"))
		})
	})

	Context("when handling empty db", func() {
		BeforeEach(func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"packages": []}`))
			}))
			manager = chainguard.NewManager(testServer.URL, config)
		})

		It("should return empty map for empty packages", func() {
			ctx := context.Background()
			records, err := manager.Get(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(records).NotTo(BeNil())
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

		It("should respect context timeout", func() {
			testServer.Close()
			testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(100 * time.Millisecond)
				json.NewEncoder(w).Encode(testData)
			}))
			manager = chainguard.NewManager(testServer.URL, config)

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
